//go:build linux

package networkpolicy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// RetainedResources observes current CPU/memory/swap/process enforcement for an
// owned mapped child. It does not prove cgroup placement at birth, disk quota,
// exclusive reservation, authority, cleanup or runtime identity.
// A trusted launcher must use CLONE_INTO_CGROUP before the child allocates memory.
// No cgroup is created, modified, adopted by pathname, killed or removed here.
type RetainedResources struct {
	mu              sync.Mutex
	scope           *os.File
	child           *ChildNamespaces
	owner           *Authority
	ceiling         resourceLimits
	state           resourceState
	invalid, closed bool
}

func RetainResources(job *p.JobSpecification, child *ChildNamespaces, scope *os.File) (*RetainedResources, error) {
	owner, err := NewAuthority(job)
	if err != nil || os.Getuid() != 0 || os.Geteuid() != 0 || child == nil || scope == nil || job.EffectivePolicy.Sandbox != p.SandboxKind_SANDBOX_KIND_GVISOR || job.EffectivePolicy.Resources.ProcessCount > 4096 {
		return nil, ErrResources
	}
	limits := job.EffectivePolicy.Resources
	fd, err := unix.FcntlInt(scope.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, ErrResources
	}
	r := &RetainedResources{scope: os.NewFile(uintptr(fd), "owned-runtime-cgroup"), child: child, owner: owner,
		ceiling: resourceLimits{uint64(limits.CpuMillis), limits.MemoryBytes, uint64(limits.ProcessCount) + MappedRuntimeProcessReserve}}
	r.mu.Lock()
	r.state, err = r.observeLocked()
	r.mu.Unlock()
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func protectedCgroup(file *os.File, directory bool) bool {
	if file == nil {
		return false
	}
	var fs unix.Statfs_t
	var st unix.Stat_t
	kind := uint32(unix.S_IFREG)
	if directory {
		kind = unix.S_IFDIR
	}
	return unix.Fstatfs(int(file.Fd()), &fs) == nil && fs.Type == unix.CGROUP2_SUPER_MAGIC && unix.Fstat(int(file.Fd()), &st) == nil && st.Mode&unix.S_IFMT == kind && st.Uid == 0 && st.Mode&0022 == 0 && st.Nlink > 0
}

func unifiedCgroupPath(raw string) (string, bool) {
	if len(raw) == 0 || len(raw) > 16384 || !strings.HasPrefix(raw, "0::/") || !strings.HasSuffix(raw, "\n") {
		return "", false
	}
	path := strings.TrimSuffix(strings.TrimPrefix(raw, "0::"), "\n")
	return path, filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func fairScheduler(stat, limits string) bool {
	// comm is parenthesized and may itself contain parentheses or spaces.
	end := strings.LastIndex(stat, ")")
	if end < 0 || len(stat) > 16384 || len(limits) > 16384 {
		return false
	}
	fields := strings.Fields(stat[end+1:])
	// Field 41 is scheduling policy; fields starts at field 3 (state).
	if len(fields) < 39 || (fields[38] != "0" && fields[38] != "3" && fields[38] != "5") {
		return false
	}
	found := false
	for _, line := range strings.Split(limits, "\n") {
		if strings.HasPrefix(line, "Max realtime priority") {
			if found || strings.Join(strings.Fields(line), " ") != "Max realtime priority 0 0" {
				return false
			}
			found = true
		}
	}
	return found
}

// Scheduling policy is per-thread. Checking only the leader could overlook an
// already-realtime worker even when the shared priority limit has become zero.
func fairChildThreads(child *ChildNamespaces, limits string, maximum uint64) bool {
	tasks, err := child.open("task", true)
	if err != nil {
		return false
	}
	defer tasks.Close()
	entries, err := tasks.ReadDir(int(maximum) + 1)
	if (err != nil && err != io.EOF) || len(entries) == 0 || uint64(len(entries)) > maximum {
		return false
	}
	for _, entry := range entries {
		id, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || id == 0 || strconv.FormatUint(id, 10) != entry.Name() || !entry.IsDir() {
			return false
		}
		fd, err := unix.Openat2(int(tasks.Fd()), entry.Name()+"/stat", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return false
		}
		file := os.NewFile(uintptr(fd), "owned-child-thread-stat")
		raw, readErr := io.ReadAll(io.LimitReader(file, 16385))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || !fairScheduler(string(raw), limits) {
			return false
		}
	}
	return true
}

func (r *RetainedResources) observeLocked() (resourceState, error) {
	if r.closed || r.invalid || r.child == nil || !protectedCgroup(r.scope, true) {
		return resourceState{}, ErrResources
	}
	child := r.child
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.validateLocked(r.owner.lease.JobId) != nil {
		return resourceState{}, fmt.Errorf("%w: initial child identity", ErrResources)
	}
	processStat, err := child.read("stat")
	if err != nil {
		return resourceState{}, fmt.Errorf("%w: leader scheduling read", ErrResources)
	}
	processLimits, err := child.read("limits")
	if err != nil || !fairScheduler(processStat, processLimits) {
		return resourceState{}, fmt.Errorf("%w: leader scheduling policy", ErrResources)
	}
	if !fairChildThreads(child, processLimits, r.ceiling.processes) {
		return resourceState{}, fmt.Errorf("%w: thread scheduling observation", ErrResources)
	}
	raw, err := child.read("cgroup")
	path, ok := unifiedCgroupPath(raw)
	if err != nil || !ok {
		return resourceState{}, ErrResources
	}
	base, err := os.OpenFile("/sys/fs/cgroup", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return resourceState{}, ErrResources
	}
	defer base.Close()
	if !protectedCgroup(base, true) {
		return resourceState{}, ErrResources
	}
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		path = "."
	}
	fd, err := unix.Openat2(int(base.Fd()), path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return resourceState{}, ErrResources
	}
	current := os.NewFile(uintptr(fd), "observed-child-cgroup")
	defer current.Close()
	var a, b unix.Stat_t
	if unix.Fstat(fd, &a) != nil || unix.Fstat(int(r.scope.Fd()), &b) != nil || a.Dev != b.Dev || a.Ino != b.Ino {
		return resourceState{}, ErrResources
	}
	values := make(map[string]string, 6)
	for _, name := range []string{"cgroup.type", "memory.max", "memory.swap.max", "cpu.max", "cpu.max.burst", "pids.max", "cgroup.procs", "cgroup.threads"} {
		fd, err := unix.Openat2(int(r.scope.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return resourceState{}, ErrResources
		}
		file := os.NewFile(uintptr(fd), "owned-cgroup-control")
		if !protectedCgroup(file, false) {
			file.Close()
			return resourceState{}, ErrResources
		}
		if name != "cgroup.procs" && name != "cgroup.threads" {
			raw, err := io.ReadAll(io.LimitReader(file, 4097))
			if err != nil || len(raw) > 4096 {
				file.Close()
				return resourceState{}, ErrResources
			}
			values[name] = string(raw)
		}
		if file.Close() != nil {
			return resourceState{}, ErrResources
		}
	}
	state, err := readResourceState(values, r.ceiling)
	if err != nil || child.validateLocked(r.owner.lease.JobId) != nil {
		return resourceState{}, fmt.Errorf("%w: limits or final child identity", ErrResources)
	}
	// A concurrent trusted-controller migration must not be mistaken for the
	// originally observed membership. The retained directory never follows names.
	final, err := child.read("cgroup")
	if err != nil || final != raw {
		return resourceState{}, fmt.Errorf("%w: cgroup membership changed", ErrResources)
	}
	finalLimits, err := child.read("limits")
	if err != nil || finalLimits != processLimits {
		return resourceState{}, fmt.Errorf("%w: process limits changed", ErrResources)
	}
	return state, nil
}

func (r *RetainedResources) Validate(job *p.JobSpecification) error {
	if r == nil {
		return ErrResources
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	owner, err := NewAuthority(job)
	if err != nil || r.owner == nil || owner.digest != r.owner.digest || owner.lease.JobId != r.owner.lease.JobId || owner.lease.LeaseId != r.owner.lease.LeaseId || owner.lease.ExecutionId != r.owner.lease.ExecutionId || !proto.Equal(owner.attempt, r.owner.attempt) {
		r.invalid = true
		return ErrResources
	}
	state, err := r.observeLocked()
	if err != nil || state != r.state {
		r.invalid = true
		return ErrResources
	}
	return nil
}

// Close releases only this object's descriptor. It neither kills the child nor
// proves process, route, workspace or cgroup cleanup. Refusal is never repaired.
func (r *RetainedResources) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.scope != nil && r.scope.Close() != nil {
		return ErrResources
	}
	return nil
}
