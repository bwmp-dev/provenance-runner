//go:build linux

package runtimeidentity

import "golang.org/x/sys/unix"

// ValidatePaperGuestTarget checks the fixed helper in the retained measured
// image. The complete image digest is the authority, not this pathname alone.
func (l *Lease) ValidatePaperGuestTarget() error {
	if l == nil {
		return ErrUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.validateLocked() != nil {
		return ErrUnavailable
	}
	fd, err := unix.Openat2(int(l.root.Fd()), "provenance-measured-paper", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return ErrUnavailable
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	valid := unix.Fstat(fd, &st) == nil && st.Mode == unix.S_IFREG|0555 && st.Size > 0 && st.Size <= 32<<20 && unix.Fstatfs(fd, &fs) == nil && fs.Type == unix.SQUASHFS_MAGIC
	if unix.Close(fd) != nil || !valid || l.validateLocked() != nil {
		return ErrUnavailable
	}
	return nil
}
