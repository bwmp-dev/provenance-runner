package instancelock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrAlreadyHeld = errors.New("runner instance lock is already held")

type Lock struct {
	mu     sync.Mutex
	file   *os.File
	closed bool
}

type metadata struct {
	PID        int       `json:"pid"`
	AcquiredAt time.Time `json:"acquiredAt"`
}

func Acquire(path string) (*Lock, error) {
	if path == "" {
		return nil, errors.New("acquire runner instance lock: path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("acquire runner instance lock: resolve path: %w", err)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("acquire runner instance lock: create parent: %w", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return nil, fmt.Errorf("acquire runner instance lock: restrict parent: %w", err)
	}
	if info, err := os.Lstat(absolute); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("acquire runner instance lock: existing lock path is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("acquire runner instance lock: inspect path: %w", err)
	}
	file, err := os.OpenFile(absolute, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("acquire runner instance lock: open file: %w", err)
	}
	if err := os.Chmod(absolute, 0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("acquire runner instance lock: restrict file: %w", err)
	}
	if err := lockFile(file); err != nil {
		file.Close()
		if isLockContention(err) {
			return nil, fmt.Errorf("%w: %s", ErrAlreadyHeld, absolute)
		}
		return nil, fmt.Errorf("acquire runner instance lock: lock file: %w", err)
	}
	encoded, err := json.Marshal(metadata{PID: os.Getpid(), AcquiredAt: time.Now().UTC()})
	if err == nil {
		encoded = append(encoded, '\n')
		err = file.Truncate(0)
	}
	if err == nil {
		_, err = file.WriteAt(encoded, 0)
	}
	if err == nil {
		err = file.Sync()
	}
	if err != nil {
		unlockErr := unlockFile(file)
		closeErr := file.Close()
		return nil, errors.Join(fmt.Errorf("acquire runner instance lock: write metadata: %w", err), unlockErr, closeErr)
	}
	return &Lock{file: file}, nil
}

func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return errors.Join(unlockFile(l.file), l.file.Close())
}
