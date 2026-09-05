//go:build !linux

package gvisor

import (
	"errors"
	"os"
)

func requireReadOnlyFilesystem(string) error {
	return errors.New("read-only root filesystem validation requires Linux")
}

func rootFSOwnership(string) (uint32, uint32, error) {
	return 0, 0, errors.New("root filesystem ownership validation requires Linux")
}

func rootFSCurrentIdentity() (uint32, uint32) {
	return 0, 0
}

func rootFSGuestShellMode(string) (os.FileMode, bool, error) {
	return 0, false, errors.New("root filesystem guest shell validation requires Linux")
}
