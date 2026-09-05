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
