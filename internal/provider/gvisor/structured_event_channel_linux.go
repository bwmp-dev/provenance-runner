//go:build linux

package gvisor

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func makeHostFIFO(path string, mode uint32) error {
	return unix.Mkfifo(path, mode)
}

func openHostFIFO(path string) (*os.File, *os.File, error) {
	readerFD, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	reader := os.NewFile(uintptr(readerFD), path)
	keepaliveFD, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = reader.Close()
		return nil, nil, err
	}
	return reader, os.NewFile(uintptr(keepaliveFD), path), nil
}

func readHostFIFO(file *os.File, buffer []byte) (int, error) {
	return unix.Read(int(file.Fd()), buffer)
}

func hostFIFOWouldBlock(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK)
}
