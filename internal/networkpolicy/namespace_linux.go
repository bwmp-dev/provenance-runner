//go:build linux

package networkpolicy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var ErrNamespace = errors.New("network_namespace_identity_unavailable")

// MappedIdentity is trusted provisioning input, never workload-supplied identity.
// Namespace root and overflow each have one distinct non-root host UID/GID.
type MappedIdentity struct{ UID, GID, OverflowUID, OverflowGID uint32 }

// ChildNamespaces retains kernel objects for a controller's direct living child.
// It proves neither gateway authority nor installed packet enforcement. It does
// not create/adopt host routes, kill workloads, or delete namespace resources.
type ChildNamespaces struct {
	mu                         sync.Mutex
	job                        string
	mapping                    MappedIdentity
	proc, network, user, pidfd *os.File
	closed                     bool
}

// RetainMappedChild accepts only the caller's own direct child in a fresh mapped
// user/network namespace. A pidfd is opened before procfs: exit/PID reuse cannot
// convert a stale child number into authority over a replacement process.
// Callers must create and own the child themselves; no public PID/path endpoint
// or production capability is introduced by this internal verification boundary.
func RetainMappedChild(job string, child *os.Process, mapping MappedIdentity) (result *ChildNamespaces, err error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || child == nil || child.Pid <= 1 || child.Pid == os.Getpid() || !jobID.MatchString(job) || job == "00000000-0000-0000-0000-000000000000" || !validMappedIdentity(mapping) {
		return nil, ErrNamespace
	}
	s := &ChildNamespaces{job: job, mapping: mapping}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	fd, e := unix.PidfdOpen(child.Pid, 0)
	if e != nil {
		return nil, ErrNamespace
	}
	s.pidfd = os.NewFile(uintptr(fd), "owned-child-pidfd")
	fd, e = unix.Open("/proc/"+strconv.Itoa(child.Pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrNamespace
	}
	s.proc = os.NewFile(uintptr(fd), "owned-child-proc")
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, ErrNamespace
	}
	s.network, e = s.open("ns/net", false)
	if e != nil {
		return nil, ErrNamespace
	}
	s.user, e = s.open("ns/user", false)
	if e != nil {
		return nil, ErrNamespace
	}
	if s.validateLocked(job) != nil {
		return nil, ErrNamespace
	}
	return s, nil
}

func validMappedIdentity(m MappedIdentity) bool {
	for _, id := range []uint32{m.UID, m.GID, m.OverflowUID, m.OverflowGID} {
		if id == 0 || id == ^uint32(0) {
			return false
		}
	}
	return m.UID != m.OverflowUID && m.GID != m.OverflowGID
}

func (s *ChildNamespaces) open(name string, noFollow bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC
	if noFollow {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Openat(int(s.proc.Fd()), name, flags, 0)
	if err != nil {
		return nil, ErrNamespace
	}
	return os.NewFile(uintptr(fd), "owned-child-field"), nil
}

func (s *ChildNamespaces) read(name string) (string, error) {
	f, err := s.open(name, true)
	if err != nil {
		return "", ErrNamespace
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return "", ErrNamespace
	}
	return string(raw), nil
}

func sameNamespace(a, b *os.File, kind int) bool {
	if a == nil || b == nil {
		return false
	}
	var left, right unix.Stat_t
	if unix.Fstat(int(a.Fd()), &left) != nil || unix.Fstat(int(b.Fd()), &right) != nil || left.Dev != right.Dev || left.Ino != right.Ino {
		return false
	}
	for _, file := range []*os.File{a, b} {
		var fs unix.Statfs_t
		got, err := unix.IoctlRetInt(int(file.Fd()), unix.NS_GET_NSTYPE)
		if err != nil || got != kind || unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Type != unix.NSFS_MAGIC {
			return false
		}
	}
	return true
}

func (s *ChildNamespaces) validateLocked(job string) error {
	if s.closed || s.proc == nil || s.pidfd == nil || job != s.job {
		return ErrNamespace
	}
	poll := []unix.PollFd{{Fd: int32(s.pidfd.Fd()), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 0); err != nil || n != 0 || poll[0].Revents != 0 {
		return ErrNamespace
	}
	status, err := s.read("status")
	if err != nil {
		return ErrNamespace
	}
	fields := map[string][]string{}
	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[key] = strings.Fields(value)
		}
	}
	groups, groupsPresent := fields["Groups"]
	if strings.Join(fields["PPid"], " ") != strconv.Itoa(os.Getpid()) || !groupsPresent || len(groups) != 0 {
		return ErrNamespace
	}
	for name, want := range map[string]uint32{"Uid": s.mapping.UID, "Gid": s.mapping.GID} {
		if len(fields[name]) != 4 {
			return ErrNamespace
		}
		for _, id := range fields[name] {
			if id != strconv.FormatUint(uint64(want), 10) {
				return ErrNamespace
			}
		}
	}
	for name, expected := range map[string]string{
		"uid_map":   fmt.Sprintf("0 %d 1 65534 %d 1", s.mapping.UID, s.mapping.OverflowUID),
		"gid_map":   fmt.Sprintf("0 %d 1 65534 %d 1", s.mapping.GID, s.mapping.OverflowGID),
		"setgroups": "deny",
	} {
		value, err := s.read(name)
		if err != nil || strings.Join(strings.Fields(value), " ") != expected {
			return ErrNamespace
		}
	}
	currentNet, err := s.open("ns/net", false)
	if err != nil {
		return ErrNamespace
	}
	defer currentNet.Close()
	currentUser, err := s.open("ns/user", false)
	if err != nil {
		return ErrNamespace
	}
	defer currentUser.Close()
	if !sameNamespace(s.network, currentNet, unix.CLONE_NEWNET) || !sameNamespace(s.user, currentUser, unix.CLONE_NEWUSER) {
		return ErrNamespace
	}
	selfNet, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return ErrNamespace
	}
	defer selfNet.Close()
	selfUser, err := os.Open("/proc/self/ns/user")
	if err != nil {
		return ErrNamespace
	}
	defer selfUser.Close()
	if sameNamespace(s.network, selfNet, unix.CLONE_NEWNET) || sameNamespace(s.user, selfUser, unix.CLONE_NEWUSER) {
		return ErrNamespace
	}
	ownerFD, err := unix.IoctlRetInt(int(s.network.Fd()), unix.NS_GET_USERNS)
	if err != nil {
		return ErrNamespace
	}
	owner := os.NewFile(uintptr(ownerFD), "owned-network-user")
	defer owner.Close()
	parentFD, err := unix.IoctlRetInt(int(s.user.Fd()), unix.NS_GET_PARENT)
	if err != nil {
		return ErrNamespace
	}
	parent := os.NewFile(uintptr(parentFD), "owned-user-parent")
	defer parent.Close()
	if !sameNamespace(owner, s.user, unix.CLONE_NEWUSER) || !sameNamespace(parent, selfUser, unix.CLONE_NEWUSER) {
		return ErrNamespace
	}
	// Recheck liveness after all procfs reads and namespace ownership ioctls.
	if n, err := unix.Poll(poll, 0); err != nil || n != 0 || poll[0].Revents != 0 {
		return ErrNamespace
	}
	return nil
}

func (s *ChildNamespaces) Validate(job string) error {
	if s == nil {
		return ErrNamespace
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.validateLocked(job)
}

// NetworkForJob duplicates only the retained kernel object, after current child
// and job validation. The trusted caller owns the duplicate and must close it;
// a descriptor is not permission to attach a route or advertise network support.
func (s *ChildNamespaces) NetworkForJob(job string) (*os.File, error) {
	if s == nil {
		return nil, ErrNamespace
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.validateLocked(job) != nil {
		return nil, ErrNamespace
	}
	fd, err := unix.FcntlInt(s.network.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, ErrNamespace
	}
	return os.NewFile(uintptr(fd), "owned-job-network"), nil
}

// Close releases references only. It does not claim the child, routes or cgroups
// have stopped; the owning controller must complete that independent teardown.
func (s *ChildNamespaces) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var result error
	for _, f := range []*os.File{s.network, s.user, s.proc, s.pidfd} {
		if f != nil && f.Close() != nil {
			result = ErrNamespace
		}
	}
	return result
}
