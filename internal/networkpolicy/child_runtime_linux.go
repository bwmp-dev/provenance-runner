//go:build linux

package networkpolicy

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// RuntimeObjectsForJob opens the current executable and closed private-root
// location through this direct child's retained procfs directory. This is only
// an object observation, not proof of a measured runtime or installed policy.
// The trusted caller owns both returned descriptors. No PID or generic path
// endpoint is introduced.
func (s *ChildNamespaces) RuntimeObjectsForJob(job, privateRoot string) (executable, root *os.File, err error) {
	if s == nil || !filepath.IsAbs(privateRoot) || filepath.Clean(privateRoot) != privateRoot || len(privateRoot) > 4096 || strings.ContainsAny(privateRoot, "\x00\r\n") || filepath.Base(privateRoot) != ".measured-root" || filepath.Base(filepath.Dir(privateRoot)) != job {
		return nil, nil, ErrNamespace
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if err != nil {
			if executable != nil {
				executable.Close()
			}
			if root != nil {
				root.Close()
			}
			executable, root = nil, nil
		}
	}()
	if err = s.validateLocked(job); err != nil {
		return
	}
	// These two fixed procfs magic links intentionally identify this living
	// process. All traversal after its root is retained forbids symlinks.
	executable, err = s.open("exe", false)
	if err != nil {
		return
	}
	fd, openErr := unix.Openat(int(s.proc.Fd()), "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if openErr != nil {
		err = ErrNamespace
		return
	}
	processRoot := os.NewFile(uintptr(fd), "owned-child-root")
	defer processRoot.Close()
	fd, openErr = unix.Openat2(fd, strings.TrimPrefix(privateRoot, "/"), &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if openErr != nil {
		err = ErrNamespace
		return
	}
	root = os.NewFile(uintptr(fd), "owned-child-private-root")
	err = s.validateLocked(job)
	return
}
