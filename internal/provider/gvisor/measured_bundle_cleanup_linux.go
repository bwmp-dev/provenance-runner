//go:build linux

package gvisor

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

var errMeasuredBundle = errors.New("measured_bundle_ownership_unavailable")

// removeMeasuredBundleContents is called only after the owning journal has
// proved the top-level directory identity and completed whole-scope cleanup.
// Never follow guest symlinks or cross even a same-filesystem bind mount. The
// entry/depth bounds prevent hostile trees from making recovery unbounded.
func removeMeasuredBundleContents(ctx context.Context, directory *os.File, remaining *int, depth int) error {
	if ctx == nil || ctx.Err() != nil || directory == nil || remaining == nil || *remaining <= 0 || depth > 32 {
		return errMeasuredBundle
	}
	fd, err := unix.Openat2(int(directory.Fd()), ".", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return errMeasuredBundle
	}
	view := os.NewFile(uintptr(fd), "owned-bundle-cleanup-view")
	defer view.Close()
	for {
		entries, readErr := view.ReadDir(32)
		if readErr != nil && readErr != io.EOF {
			return errMeasuredBundle
		}
		for _, entry := range entries {
			if ctx.Err() != nil || *remaining <= 0 {
				return errMeasuredBundle
			}
			*remaining--
			var before unix.Stat_t
			if unix.Fstatat(fd, entry.Name(), &before, unix.AT_SYMLINK_NOFOLLOW) != nil {
				return errMeasuredBundle
			}
			if before.Mode&unix.S_IFMT == unix.S_IFDIR {
				childFD, err := unix.Openat2(fd, entry.Name(), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
					Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
				if err != nil {
					return errMeasuredBundle
				}
				child := os.NewFile(uintptr(childFD), "owned-bundle-cleanup-child")
				var retained unix.Stat_t
				if unix.Fstat(childFD, &retained) != nil || retained.Dev != before.Dev || retained.Ino != before.Ino {
					child.Close()
					return errMeasuredBundle
				}
				err = removeMeasuredBundleContents(ctx, child, remaining, depth+1)
				closeErr := child.Close()
				if err != nil || closeErr != nil {
					return errMeasuredBundle
				}
			}
			var current unix.Stat_t
			if unix.Fstatat(fd, entry.Name(), &current, unix.AT_SYMLINK_NOFOLLOW) != nil || current.Dev != before.Dev || current.Ino != before.Ino || current.Mode&unix.S_IFMT != before.Mode&unix.S_IFMT {
				return errMeasuredBundle
			}
			flags := 0
			if before.Mode&unix.S_IFMT == unix.S_IFDIR {
				flags = unix.AT_REMOVEDIR
			}
			if unix.Unlinkat(fd, entry.Name(), flags) != nil {
				return errMeasuredBundle
			}
		}
		if readErr == io.EOF {
			if directory.Sync() != nil {
				return errMeasuredBundle
			}
			return nil
		}
	}
}
