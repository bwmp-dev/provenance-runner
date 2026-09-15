//go:build linux

package networkpolicy

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// JobCgroup owns only a newly created, root-protected leaf beneath an explicitly
// provisioned parent. It never adopts an existing job directory. This is not a
// crash-recovery journal, disk quota, route teardown, or capacity-release proof.
type JobCgroup struct {
	mu                sync.Mutex
	parent, scope     *os.File
	name              string
	owner             *Authority
	ceiling           resourceLimits
	state             resourceState
	stopping, removed bool
}

func cgroupControl(scope *os.File, name string, flags uint64) (*os.File, error) {
	if !protectedCgroup(scope, true) {
		return nil, ErrResources
	}
	fd, err := unix.Openat2(int(scope.Fd()), name, &unix.OpenHow{Flags: flags | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, ErrResources
	}
	f := os.NewFile(uintptr(fd), "owned-job-cgroup-control")
	if !protectedCgroup(f, false) {
		f.Close()
		return nil, ErrResources
	}
	return f, nil
}

func readCgroupControl(scope *os.File, name string) (string, error) {
	f, err := cgroupControl(scope, name, unix.O_RDONLY)
	if err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	closed := f.Close()
	if err != nil || closed != nil || len(raw) > 4096 {
		return "", ErrResources
	}
	return string(raw), nil
}

func writeCgroupControl(scope *os.File, name, value string) error {
	f, err := cgroupControl(scope, name, unix.O_WRONLY)
	if err != nil {
		return err
	}
	n, err := f.WriteString(value)
	closed := f.Close()
	if err != nil || closed != nil || n != len(value) {
		return ErrResources
	}
	return nil
}

// CreateJobCgroup requires a trusted, empty, non-root cgroup parent with cpu,
// memory and pids already enabled. It does not enable or change parent controls.
// A non-nil result ALWAYS belongs to the caller, even on configuration failure:
// call Cleanup until successful. Existing names are refused without mutation.
func CreateJobCgroup(job *p.JobSpecification, parent *os.File) (*JobCgroup, error) {
	owner, err := NewAuthority(job)
	if err != nil || os.Getuid() != 0 || os.Geteuid() != 0 || !protectedCgroup(parent, true) || job.EffectivePolicy.Sandbox != p.SandboxKind_SANDBOX_KIND_GVISOR || job.EffectivePolicy.Resources.ProcessCount > 4096 {
		return nil, ErrResources
	}
	root, err := os.Open("/sys/fs/cgroup")
	if err != nil {
		return nil, ErrResources
	}
	a, e1 := parent.Stat()
	b, e2 := root.Stat()
	root.Close()
	if e1 != nil || e2 != nil || os.SameFile(a, b) {
		return nil, ErrResources
	}
	if raw, err := readCgroupControl(parent, "cgroup.procs"); err != nil || raw != "" {
		return nil, ErrResources
	}
	if raw, err := readCgroupControl(parent, "cgroup.type"); err != nil || raw != "domain\n" {
		return nil, ErrResources
	}
	raw, err := readCgroupControl(parent, "cgroup.subtree_control")
	if err != nil {
		return nil, err
	}
	controllers := " " + strings.Join(strings.Fields(raw), " ") + " "
	for _, name := range []string{"cpu", "memory", "pids"} {
		if !strings.Contains(controllers, " "+name+" ") {
			return nil, ErrResources
		}
	}
	fd, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, ErrResources
	}
	limits := job.EffectivePolicy.Resources
	s := &JobCgroup{parent: os.NewFile(uintptr(fd), "owned-job-cgroup-parent"), name: "job-" + owner.lease.JobId + "-" + owner.attempt.AttemptId, owner: owner,
		ceiling: resourceLimits{uint64(limits.CpuMillis), limits.MemoryBytes, uint64(limits.ProcessCount) + MappedRuntimeProcessReserve}}
	if unix.Mkdirat(fd, s.name, 0700) != nil {
		s.parent.Close()
		return nil, ErrResources
	}
	child, err := unix.Openat2(fd, s.name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		// Only this exact just-created name; no recursive or parent cleanup.
		if unix.Unlinkat(fd, s.name, unix.AT_REMOVEDIR) == nil {
			s.parent.Close()
			return nil, ErrResources
		}
		s.stopping = true
		return s, ErrResources
	}
	s.scope = os.NewFile(uintptr(child), "owned-job-cgroup")
	values := [][2]string{{"cgroup.max.descendants", "0"}, {"cgroup.max.depth", "0"}, {"memory.max", strconv.FormatUint(s.ceiling.memoryBytes, 10)}, {"memory.swap.max", "0"}, {"cpu.max", strconv.FormatUint(s.ceiling.cpuMillis*100, 10) + " 100000"}, {"cpu.max.burst", "0"}, {"pids.max", strconv.FormatUint(s.ceiling.processes, 10)}}
	for _, value := range values {
		if writeCgroupControl(s.scope, value[0], value[1]) != nil {
			s.stopping = true
			return s, ErrResources
		}
	}
	s.state, err = s.observeLocked()
	if err != nil {
		s.stopping = true
		return s, err
	}
	return s, nil
}

func (s *JobCgroup) observeLocked() (resourceState, error) {
	if s.removed || !protectedCgroup(s.scope, true) || !protectedCgroup(s.parent, true) {
		return resourceState{}, ErrResources
	}
	for _, name := range []string{"cgroup.max.descendants", "cgroup.max.depth"} {
		if raw, err := readCgroupControl(s.scope, name); err != nil || raw != "0\n" {
			return resourceState{}, ErrResources
		}
	}
	values := make(map[string]string, 6)
	for _, name := range []string{"cgroup.type", "memory.max", "memory.swap.max", "cpu.max", "cpu.max.burst", "pids.max"} {
		raw, err := readCgroupControl(s.scope, name)
		if err != nil {
			return resourceState{}, err
		}
		values[name] = raw
	}
	return readResourceState(values, s.ceiling)
}

// LaunchFD returns an owned CLOEXEC descriptor for CLONE_INTO_CGROUP, not a
// migration path. The caller closes it after launch. Successful Cleanup removes
// the cgroup, so even previously duplicated descriptors cannot launch into it.
func (s *JobCgroup) LaunchFD(job *p.JobSpecification) (*os.File, error) {
	if s == nil {
		return nil, ErrResources
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, err := NewAuthority(job)
	if err != nil || s.owner == nil || owner.digest != s.owner.digest || !proto.Equal(owner.lease, s.owner.lease) || !proto.Equal(owner.attempt, s.owner.attempt) || s.stopping || s.removed {
		s.stopping = true
		return nil, ErrResources
	}
	state, err := s.observeLocked()
	if err != nil || state != s.state {
		s.stopping = true
		return nil, ErrResources
	}
	fd, err := unix.FcntlInt(s.scope.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		s.stopping = true
		return nil, ErrResources
	}
	return os.NewFile(uintptr(fd), "owned-job-launch-cgroup"), nil
}

func cgroupEmpty(raw string) bool {
	seen := false
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return false
		}
		if fields[0] == "populated" {
			if seen || fields[1] != "0" {
				return false
			}
			seen = true
		}
	}
	return seen
}

// Cleanup is irreversible and retryable. It stops new births, kills the entire
// owned leaf (including concurrent forks), observes no live processes, and
// removes only the exact retained directory. Parent and sibling scopes are never
// killed. Context expiry is a cleanup failure, never released capacity.
func (s *JobCgroup) Cleanup(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.removed {
		return nil
	}
	s.stopping = true
	if ctx == nil || ctx.Err() != nil || !protectedCgroup(s.scope, true) {
		return ErrResources
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if writeCgroupControl(s.scope, "pids.max", "0") != nil {
		return ErrResources
	}
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrResources, err)
		}
		if writeCgroupControl(s.scope, "cgroup.kill", "1") != nil {
			return ErrResources
		}
		raw, err := readCgroupControl(s.scope, "cgroup.events")
		if err != nil {
			return err
		}
		if cgroupEmpty(raw) {
			fd, err := unix.Openat2(int(s.parent.Fd()), s.name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
			if err != nil {
				return ErrResources
			}
			current := os.NewFile(uintptr(fd), "owned-job-cgroup-removal-check")
			a, e1 := current.Stat()
			b, e2 := s.scope.Stat()
			current.Close()
			if e1 != nil || e2 != nil || !os.SameFile(a, b) {
				return ErrResources
			}
			err = unix.Unlinkat(int(s.parent.Fd()), s.name, unix.AT_REMOVEDIR)
			if err == nil {
				s.removed = true
				return errors.Join(s.scope.Close(), s.parent.Close())
			}
			if err != unix.EBUSY {
				return ErrResources
			}
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ErrResources, ctx.Err())
		case <-timer.C:
		}
	}
}
