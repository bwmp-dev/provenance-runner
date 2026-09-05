//go:build !linux

package gvisor

import "errors"

func requireReadOnlyFilesystem(string) error {
	return errors.New("read-only root filesystem validation requires Linux")
}

func rootFSOwnership(string) (uint32, uint32, error) {
	return 0, 0, errors.New("root filesystem ownership validation requires Linux")
}

func rootFSCurrentIdentity() (uint32, uint32) {
	return 0, 0
}
