package instancelock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrAlreadyHeld = errors.New("runner instance lock is already held")

type Lock struct {
	mu     sync.Mutex
	file   *os.File
	closed bool
}

type Set struct {
	mu     sync.Mutex
	locks  []*Lock
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

func AcquireAll(paths ...string) (*Set, error) {
	unique := make(map[string]string, len(paths))
	for _, path := range paths {
		canonical, err := canonicalLockPath(path)
		if err != nil {
			return nil, err
		}
		key := canonical
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		unique[key] = canonical
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	// Canonical ordering prevents overlapping lock sets from acquiring the same
	// roots in opposite orders.
	sort.Strings(keys)

	set := &Set{locks: make([]*Lock, 0, len(keys))}
	for _, key := range keys {
		lock, err := Acquire(unique[key])
		if err != nil {
			return nil, errors.Join(err, set.Close())
		}
		set.locks = append(set.locks, lock)
	}
	return set, nil
}

func canonicalLockPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("acquire runner instance lock set: path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("acquire runner instance lock set: resolve path: %w", err)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("acquire runner instance lock set: create parent: %w", err)
	}
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("acquire runner instance lock set: resolve parent: %w", err)
	}
	return filepath.Join(canonicalParent, filepath.Base(absolute)), nil
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

func (s *Set) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var closeErrors []error
	for index := len(s.locks) - 1; index >= 0; index-- {
		if err := s.locks[index].Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	return errors.Join(closeErrors...)
}
