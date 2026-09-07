//go:build linux

package runtimeidentity

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// CloneIntoNamespace rebinds a retained mount into the caller's private mount
// namespace. The kernel rejects cloning the inherited old-namespace mount FD;
// reopen its kernel path with no symlinks, prove the same mount root and actual
// image mapping, then clone that OPENED object. No pathname is reacquired after
// validation. Original image ownership/publication protection is established by
// Acquire before user-ID mapping; donated descriptors cannot change ownership
// simply because the root UID becomes unmapped in the child namespace.
func CloneIntoNamespace(root, image, loop *os.File, expectedImageSHA, destination string) error {
	if root == nil || image == nil || loop == nil || !digestPattern.MatchString(expectedImageSHA) || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return ErrDrift
	}
	var original, imageStat, loopStat unix.Stat_t
	if unix.Fstat(int(root.Fd()), &original) != nil || original.Mode&unix.S_IFMT != unix.S_IFDIR || unix.Fstat(int(image.Fd()), &imageStat) != nil || imageStat.Mode&unix.S_IFMT != unix.S_IFREG || imageStat.Nlink != 1 || imageStat.Mode&06022 != 0 || unix.Fstat(int(loop.Fd()), &loopStat) != nil || loopStat.Mode&unix.S_IFMT != unix.S_IFBLK || unix.Major(uint64(loopStat.Rdev)) != 7 {
		return ErrDrift
	}
	path, err := os.Readlink(reference(root))
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrDrift
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return ErrDrift
	}
	rebound := os.NewFile(uintptr(fd), "namespace-root")
	defer rebound.Close()
	var current unix.Stat_t
	if unix.Fstat(fd, &current) != nil || current.Dev != original.Dev || current.Ino != original.Ino {
		return ErrDrift
	}
	mount, err := inspectMount(rebound)
	if err != nil || mount.minor != unix.Minor(uint64(loopStat.Rdev)) {
		return ErrDrift
	}
	lease := &Lease{imageStat: imageStat}
	mapping, err := unix.IoctlLoopGetStatus64(int(loop.Fd()))
	if err != nil || !lease.validMapping(mapping) {
		return ErrDrift
	}
	hash, err := hashObject(image, maximumImageBytes, false)
	if err != nil || hash != expectedImageSHA {
		return ErrDrift
	}
	tree, err := unix.OpenTree(fd, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
	if err != nil {
		return ErrUnavailable
	}
	clone := os.NewFile(uintptr(tree), "cloned-root")
	defer clone.Close()
	if unix.MoveMount(tree, "", unix.AT_FDCWD, destination, unix.MOVE_MOUNT_F_EMPTY_PATH) != nil {
		return ErrUnavailable
	}
	actualMount, err := inspectMount(clone)
	if err != nil || actualMount.minor != mount.minor {
		return ErrDrift
	}
	after, err := unix.IoctlLoopGetStatus64(int(loop.Fd()))
	if err != nil || *mapping != *after {
		return ErrDrift
	}
	if unix.Fstat(tree, &current) != nil || current.Dev != original.Dev || current.Ino != original.Ino {
		return ErrDrift
	}
	hash, err = hashObject(image, maximumImageBytes, false)
	if err != nil || hash != expectedImageSHA {
		return ErrDrift
	}
	return nil
}
