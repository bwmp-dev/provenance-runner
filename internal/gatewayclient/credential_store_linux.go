//go:build linux

package gatewayclient

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type linuxCredentialStore struct {
	mu    sync.Mutex
	dir   *os.File
	name  string
	dev   uint64
	ino   uint64
	hooks credentialStoreHooks
}

type credentialStoreHooks struct {
	beforeWrite   func() error
	afterTempSync func(string) error
	afterExchange func(string) error
	afterDirSync  func() error
}

func openDurableCredentialStore(path string) (durableCredentialStore, error) {
	if !filepath.IsAbs(path) || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return nil, errors.New("credential store path is invalid")
	}
	directory := filepath.Dir(filepath.Clean(path))
	fd, err := unix.Openat2(unix.AT_FDCWD, directory, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, errors.New("credential store directory is unavailable")
	}
	dir := os.NewFile(uintptr(fd), directory)
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = dir.Close()
		}
	}()
	var directoryStat unix.Stat_t
	if err := unix.Fstat(fd, &directoryStat); err != nil || directoryStat.Uid != uint32(os.Geteuid()) || directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR || directoryStat.Mode&0o022 != 0 {
		return nil, errors.New("credential store directory is not owner-controlled")
	}
	name := filepath.Base(filepath.Clean(path))
	stat, err := secureCredentialStat(fd, name)
	if err != nil {
		return nil, err
	}
	store := &linuxCredentialStore{dir: dir, name: name, dev: uint64(stat.Dev), ino: stat.Ino}
	if err := store.removeStaleTemporaries(); err != nil {
		return nil, err
	}
	if err := store.verifyAtomicExchange(); err != nil {
		return nil, err
	}
	closeOnError = false
	return store, nil
}

func secureCredentialStat(directoryFD int, name string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return stat, errors.New("credential store target is unavailable")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 {
		return stat, errors.New("credential store target is not an owner-only regular file")
	}
	return stat, nil
}

func (store *linuxCredentialStore) Replace(credential []byte) error {
	if store == nil || len(credential) == 0 || len(credential) > MaximumCredentialBytes {
		return errors.New("credential replacement is unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.dir == nil {
		return errors.New("credential replacement is unavailable")
	}
	current, err := secureCredentialStat(int(store.dir.Fd()), store.name)
	if err != nil || uint64(current.Dev) != store.dev || current.Ino != store.ino {
		return errors.New("credential store target changed")
	}
	currentBytes, err := readCredentialAt(int(store.dir.Fd()), store.name)
	if err != nil {
		return err
	}
	if bytes.Equal(currentBytes, credential) {
		clear(currentBytes)
		if err := store.dir.Sync(); err != nil {
			return errors.New("credential directory durability failed")
		}
		return nil
	}
	clear(currentBytes)
	if store.hooks.beforeWrite != nil {
		if err := store.hooks.beforeWrite(); err != nil {
			return errors.New("credential replacement interrupted before write")
		}
	}
	temporaryName, temporaryFD, err := store.createTemporary()
	if err != nil {
		return err
	}
	temporary := os.NewFile(uintptr(temporaryFD), temporaryName)
	exchanged := false
	defer func() {
		if !exchanged {
			_ = zeroFile(temporary, len(credential))
			_ = temporary.Close()
			_ = unix.Unlinkat(int(store.dir.Fd()), temporaryName, 0)
			return
		}
		_ = temporary.Close()
	}()
	if err := writeAll(temporary, credential); err != nil {
		return errors.New("write replacement credential failed")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("sync replacement credential failed")
	}
	if store.hooks.afterTempSync != nil {
		if err := store.hooks.afterTempSync(temporaryName); err != nil {
			return errors.New("credential replacement interrupted after temporary sync")
		}
	}
	var temporaryStat unix.Stat_t
	if err := unix.Fstat(temporaryFD, &temporaryStat); err != nil || temporaryStat.Mode&unix.S_IFMT != unix.S_IFREG || temporaryStat.Nlink != 1 || temporaryStat.Uid != uint32(os.Geteuid()) || temporaryStat.Mode&0o7777 != 0o600 {
		return errors.New("replacement credential temporary file changed")
	}
	current, err = secureCredentialStat(int(store.dir.Fd()), store.name)
	if err != nil || uint64(current.Dev) != store.dev || current.Ino != store.ino {
		return errors.New("credential store target changed")
	}
	if err := unix.Renameat2(int(store.dir.Fd()), temporaryName, int(store.dir.Fd()), store.name, unix.RENAME_EXCHANGE); err != nil {
		return errors.New("atomic credential replacement failed")
	}
	exchanged = true
	displaced, err := secureCredentialStat(int(store.dir.Fd()), temporaryName)
	if err != nil || uint64(displaced.Dev) != store.dev || displaced.Ino != store.ino {
		_ = unix.Renameat2(int(store.dir.Fd()), temporaryName, int(store.dir.Fd()), store.name, unix.RENAME_EXCHANGE)
		return errors.New("credential store target raced with replacement")
	}
	newTarget, err := secureCredentialStat(int(store.dir.Fd()), store.name)
	if err != nil || uint64(newTarget.Dev) != uint64(temporaryStat.Dev) || newTarget.Ino != temporaryStat.Ino {
		_ = unix.Renameat2(int(store.dir.Fd()), temporaryName, int(store.dir.Fd()), store.name, unix.RENAME_EXCHANGE)
		return errors.New("credential store replacement identity is invalid")
	}
	store.dev, store.ino = uint64(newTarget.Dev), newTarget.Ino
	if store.hooks.afterExchange != nil {
		if err := store.hooks.afterExchange(temporaryName); err != nil {
			return errors.New("credential replacement interrupted after atomic exchange")
		}
	}
	if err := zeroCredentialAt(int(store.dir.Fd()), temporaryName); err != nil {
		return errors.New("clear displaced credential failed")
	}
	if err := unix.Unlinkat(int(store.dir.Fd()), temporaryName, 0); err != nil {
		return errors.New("remove displaced credential failed")
	}
	if err := store.dir.Sync(); err != nil {
		return errors.New("credential directory durability failed")
	}
	if store.hooks.afterDirSync != nil {
		if err := store.hooks.afterDirSync(); err != nil {
			return errors.New("credential replacement interrupted after directory sync")
		}
	}
	return nil
}

func (store *linuxCredentialStore) removeStaleTemporaries() error {
	names, err := store.dir.Readdirnames(-1)
	if err != nil {
		return errors.New("inspect credential store directory failed")
	}
	prefix := "." + store.name + ".rotation-"
	removed := false
	for _, name := range names {
		suffix := strings.TrimPrefix(name, prefix)
		if suffix == name || len(suffix) != 32 {
			continue
		}
		if _, err := hex.DecodeString(suffix); err != nil {
			continue
		}
		stat, err := secureCredentialStat(int(store.dir.Fd()), name)
		if err != nil || stat.Mode&0o7777 != 0o600 {
			return errors.New("stale credential temporary file is unsafe")
		}
		if err := zeroCredentialAt(int(store.dir.Fd()), name); err != nil {
			return errors.New("clear stale credential temporary file failed")
		}
		if err := unix.Unlinkat(int(store.dir.Fd()), name, 0); err != nil {
			return errors.New("remove stale credential temporary file failed")
		}
		removed = true
	}
	if removed {
		if err := store.dir.Sync(); err != nil {
			return errors.New("sync credential store cleanup failed")
		}
	}
	return nil
}

func (store *linuxCredentialStore) verifyAtomicExchange() error {
	firstName, firstFD, err := store.createTemporary()
	if err != nil {
		return err
	}
	_ = unix.Close(firstFD)
	defer unix.Unlinkat(int(store.dir.Fd()), firstName, 0)
	secondName, secondFD, err := store.createTemporary()
	if err != nil {
		return err
	}
	_ = unix.Close(secondFD)
	defer unix.Unlinkat(int(store.dir.Fd()), secondName, 0)
	if err := unix.Renameat2(int(store.dir.Fd()), firstName, int(store.dir.Fd()), secondName, unix.RENAME_EXCHANGE); err != nil {
		return errors.New("credential store lacks atomic exchange support")
	}
	if err := unix.Unlinkat(int(store.dir.Fd()), firstName, 0); err != nil {
		return errors.New("credential exchange probe cleanup failed")
	}
	if err := unix.Unlinkat(int(store.dir.Fd()), secondName, 0); err != nil {
		return errors.New("credential exchange probe cleanup failed")
	}
	if err := store.dir.Sync(); err != nil {
		return errors.New("credential exchange probe durability failed")
	}
	return nil
}

func (store *linuxCredentialStore) createTemporary() (string, int, error) {
	for range 16 {
		var suffix [16]byte
		if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
			return "", -1, errors.New("credential temporary identity generation failed")
		}
		name := fmt.Sprintf(".%s.rotation-%s", store.name, hex.EncodeToString(suffix[:]))
		fd, err := unix.Openat(int(store.dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err == nil {
			return name, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, errors.New("create replacement credential failed")
		}
	}
	return "", -1, errors.New("credential temporary identity exhausted")
}

func readCredentialAt(directoryFD int, name string) ([]byte, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open credential store target failed")
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaximumCredentialBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaximumCredentialBytes {
		clear(data)
		return nil, errors.New("read credential store target failed")
	}
	return data, nil
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		value = value[written:]
	}
	return nil
}

func zeroFile(file *os.File, size int) error {
	if file == nil || size < 1 {
		return nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := writeAll(file, make([]byte, size)); err != nil {
		return err
	}
	return file.Sync()
}

func zeroCredentialAt(directoryFD int, name string) error {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 || stat.Size < 0 || stat.Size > MaximumCredentialBytes {
		return errors.New("credential file cannot be safely cleared")
	}
	return zeroFile(file, int(stat.Size))
}

func (store *linuxCredentialStore) Close() error {
	if store == nil || store.dir == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	err := store.dir.Close()
	store.dir = nil
	return err
}
