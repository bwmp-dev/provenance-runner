//go:build !linux

package gvisor

import (
	"errors"
	"os"
)

func makeHostFIFO(string, uint32) error {
	return errors.New("host FIFOs require Linux")
}

func openHostFIFO(string) (*os.File, *os.File, error) {
	return nil, nil, errors.New("host FIFOs require Linux")
}

func readHostFIFO(*os.File, []byte) (int, error) {
	return 0, errors.New("host FIFOs require Linux")
}

func hostFIFOWouldBlock(error) bool {
	return false
}
