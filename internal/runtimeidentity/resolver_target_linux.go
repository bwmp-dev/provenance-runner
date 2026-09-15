//go:build linux

package runtimeidentity

import "golang.org/x/sys/unix"

// ValidateResolverTarget requires the fixed mount target to be a regular file
// inside the retained immutable image, not a symlink or another mounted object.
// It does not authorize arbitrary additional host-to-guest mounts.
func (l *Lease) ValidateResolverTarget() error {
	if l == nil {
		return ErrUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.validateLocked() != nil {
		return ErrUnavailable
	}
	fd, err := unix.Openat2(int(l.root.Fd()), "etc/resolv.conf", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return ErrUnavailable
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	valid := unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && unix.Fstatfs(fd, &fs) == nil && fs.Type == unix.SQUASHFS_MAGIC
	if unix.Close(fd) != nil || !valid || l.validateLocked() != nil {
		return ErrUnavailable
	}
	return nil
}
