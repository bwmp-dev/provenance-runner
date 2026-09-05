//go:build linux

package gvisor

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func rootFSOwnership(path string) (uint32, uint32, error) {
	var state unix.Stat_t
	if err := unix.Lstat(path, &state); err != nil {
		return 0, 0, err
	}
	return state.Uid, state.Gid, nil
}

func rootFSCurrentIdentity() (uint32, uint32) {
	return uint32(os.Geteuid()), uint32(os.Getegid())
}

func rootFSGuestShellMode(rootFS string) (os.FileMode, bool, error) {
	rootFD, err := unix.Open(rootFS, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, false, err
	}
	defer unix.Close(rootFD)
	shellFD, err := unix.Openat2(rootFD, "bin/sh", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return 0, false, err
	}
	defer unix.Close(shellFD)
	var state unix.Stat_t
	if err := unix.Fstat(shellFD, &state); err != nil {
		return 0, false, err
	}
	return os.FileMode(state.Mode & 0o777), state.Mode&unix.S_IFMT == unix.S_IFREG, nil
}

func requireReadOnlyFilesystem(path string) error {
	var state unix.Statfs_t
	if err := unix.Statfs(path, &state); err != nil {
		return err
	}
	if state.Flags&unix.ST_RDONLY == 0 {
		return errors.New("filesystem is writable")
	}
	return nil
}
