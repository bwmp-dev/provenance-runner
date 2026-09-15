//go:build linux

package runtimeidentity

import (
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"golang.org/x/sys/unix"
)

// ValidateChildObjects compares a living retained child's actual executable
// and mounted private root with this lease's protected objects. It does not
// infer network permission, successful execution, or terminal evidence.
func (l *Lease) ValidateChildObjects(child *np.ChildNamespaces, job, privateRoot string) error {
	if l == nil {
		return ErrUnavailable
	}
	executable, root, err := child.RuntimeObjectsForJob(job, privateRoot)
	if err != nil {
		return ErrUnavailable
	}
	defer executable.Close()
	defer root.Close()
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.validateLocked(); err != nil {
		return err
	}
	var actualExe, expectedExe, actualRoot, expectedRoot unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(int(executable.Fd()), &actualExe) != nil || unix.Fstat(int(l.sandbox.Fd()), &expectedExe) != nil || actualExe.Dev != expectedExe.Dev || actualExe.Ino != expectedExe.Ino || unix.Fstat(int(root.Fd()), &actualRoot) != nil || unix.Fstat(int(l.root.Fd()), &expectedRoot) != nil || actualRoot.Dev != expectedRoot.Dev || actualRoot.Ino != expectedRoot.Ino || unix.Fstatfs(int(root.Fd()), &fs) != nil || fs.Type != unix.SQUASHFS_MAGIC || fs.Flags&unix.ST_RDONLY == 0 {
		return ErrDrift
	}
	finalExe, finalRoot, err := child.RuntimeObjectsForJob(job, privateRoot)
	if err != nil {
		return ErrUnavailable
	}
	defer finalExe.Close()
	defer finalRoot.Close()
	var afterExe, afterRoot unix.Stat_t
	if unix.Fstat(int(finalExe.Fd()), &afterExe) != nil || unix.Fstat(int(finalRoot.Fd()), &afterRoot) != nil || afterExe.Dev != actualExe.Dev || afterExe.Ino != actualExe.Ino || afterRoot.Dev != actualRoot.Dev || afterRoot.Ino != actualRoot.Ino || unix.Fstatfs(int(finalRoot.Fd()), &fs) != nil || fs.Type != unix.SQUASHFS_MAGIC || fs.Flags&unix.ST_RDONLY == 0 {
		return ErrDrift
	}
	return nil
}
