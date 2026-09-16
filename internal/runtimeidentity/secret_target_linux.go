//go:build linux

package runtimeidentity

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// ValidateTestSecretTarget requires the fixed empty mountpoint in the pinned
// read-only image; startup never creates it inside an immutable measured root.
func (l *Lease) ValidateTestSecretTarget() error {
	if l == nil {
		return ErrUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.validateLocked() != nil {
		return ErrUnavailable
	}
	fd, err := unix.Openat2(int(l.root.Fd()), "run/provenance/test-secrets", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "measured-secret-mountpoint")
	defer f.Close()
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFDIR|0755 || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.SQUASHFS_MAGIC || fs.Flags&unix.ST_RDONLY == 0 {
		return ErrUnavailable
	}
	entries, err := f.ReadDir(1)
	if err != io.EOF || len(entries) != 0 || l.validateLocked() != nil {
		return ErrUnavailable
	}
	return nil
}
