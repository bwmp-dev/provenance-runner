//go:build !linux

package gvisor

func syncDirectory(string) error {
	return nil
}
