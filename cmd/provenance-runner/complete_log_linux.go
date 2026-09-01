//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type completeLogDestination interface {
	Write([]byte) (int, error)
	Chmod(os.FileMode) error
	Close() error
	Fd() uintptr
	Sync() error
}

type completeLogLinuxOperations struct {
	openDirectory func(string) (*os.File, error)
	openTemporary func(*os.File) (completeLogDestination, error)
	duplicate     func(completeLogDestination) (*os.File, error)
	publish       func(*os.File, *os.File, string) error
}

var osCompleteLogLinuxOperations = completeLogLinuxOperations{
	openDirectory: func(path string) (*os.File, error) {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), path), nil
	},
	openTemporary: func(directory *os.File) (completeLogDestination, error) {
		fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_WRONLY|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), "complete-log-staging"), nil
	},
	duplicate: func(destination completeLogDestination) (*os.File, error) {
		fd, err := unix.FcntlInt(destination.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), "complete-log-anchor"), nil
	},
	publish: func(anchor, directory *os.File, name string) error {
		// AT_EMPTY_PATH requires CAP_DAC_READ_SEARCH even when the caller owns
		// the O_TMPFILE inode. Keep the runner unprivileged and link the anchored
		// descriptor through procfs instead. AT_SYMLINK_FOLLOW resolves only the
		// kernel-owned /proc/self/fd entry; the destination remains relative to
		// the already-open directory and linkat still refuses replacement.
		source := fmt.Sprintf("/proc/self/fd/%d", anchor.Fd())
		return unix.Linkat(unix.AT_FDCWD, source, int(directory.Fd()), name, unix.AT_SYMLINK_FOLLOW)
	},
}

func exportCompleteLogFile(path string, source io.Reader) error {
	return exportCompleteLogFileWithOperations(path, source, osCompleteLogLinuxOperations)
}

func exportCompleteLogFileWithOperations(path string, source io.Reader, operations completeLogLinuxOperations) error {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve destination: %w", err)
	}
	directory, err := operations.openDirectory(filepath.Dir(absolutePath))
	if err != nil {
		return fmt.Errorf("open destination directory: %w", err)
	}
	exportErr := exportCompleteLogToDirectory(directory, filepath.Base(absolutePath), source, operations)
	return errors.Join(exportErr, wrapCompleteLogError("close destination directory", directory.Close()))
}

func exportCompleteLogToDirectory(directory *os.File, destinationName string, source io.Reader, operations completeLogLinuxOperations) error {
	destination, err := operations.openTemporary(directory)
	if err != nil {
		return fmt.Errorf("create unnamed staging file: %w", err)
	}
	if err := destination.Chmod(0o600); err != nil {
		return errors.Join(fmt.Errorf("set staging file permissions: %w", err), wrapCompleteLogError("close staging file", destination.Close()))
	}
	if _, err := io.Copy(destination, source); err != nil {
		return errors.Join(fmt.Errorf("write staging file: %w", err), wrapCompleteLogError("close staging file", destination.Close()))
	}
	if err := destination.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync staging file: %w", err), wrapCompleteLogError("close staging file", destination.Close()))
	}
	anchor, err := operations.duplicate(destination)
	if err != nil {
		return errors.Join(fmt.Errorf("anchor staging file: %w", err), wrapCompleteLogError("close staging file", destination.Close()))
	}
	if err := destination.Close(); err != nil {
		return errors.Join(fmt.Errorf("close staging file: %w", err), wrapCompleteLogError("close staging anchor", anchor.Close()))
	}
	if err := operations.publish(anchor, directory, destinationName); err != nil {
		return errors.Join(fmt.Errorf("publish destination: %w", err), wrapCompleteLogError("close staging anchor", anchor.Close()))
	}
	if err := directory.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync destination directory: %w", err), wrapCompleteLogError("close staging anchor", anchor.Close()))
	}
	return wrapCompleteLogError("close staging anchor", anchor.Close())
}
