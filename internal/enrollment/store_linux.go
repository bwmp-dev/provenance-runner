//go:build linux

package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bwmp-dev/provenance-runner/internal/runneridentity"
	"golang.org/x/sys/unix"
)

type secureTarget struct {
	dir  *os.File
	name string
}

type linuxStore struct {
	identity   secureTarget
	credential secureTarget
	token      secureTarget
	lock       *os.File
	hooks      storeHooks
}

type storeHooks struct {
	afterIdentityTempSync func() error
	afterIdentityRename   func() error
	afterCredentialSync   func() error
}

func openStore(identityPath, credentialPath, tokenPath string) (enrollmentStore, error) {
	identity, err := openSecureTarget(identityPath)
	if err != nil {
		return nil, fmt.Errorf("open runner identity store: %w", err)
	}
	store := &linuxStore{identity: identity}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = store.Close()
		}
	}()
	store.credential, err = openSecureTarget(credentialPath)
	if err != nil {
		return nil, fmt.Errorf("open credential store: %w", err)
	}
	store.token, err = openSecureTarget(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("open registration token store: %w", err)
	}
	lockName := "." + identity.name + ".enrollment.lock"
	lockFD, err := unix.Openat(int(identity.dir.Fd()), lockName, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open enrollment lock failed")
	}
	store.lock = os.NewFile(uintptr(lockFD), lockName)
	stat, err := checkedStat(lockFD, 4096)
	if err != nil || stat.Mode&0o7777 != 0o600 {
		return nil, errors.New("enrollment lock is unsafe")
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.New("another enrollment is already running")
	}
	if err := store.cleanupTemporaries(store.identity, runneridentity.MaximumDocumentBytes, ".enroll-"); err != nil {
		return nil, err
	}
	if err := store.cleanupTemporaries(store.credential, 4096, ".enroll-"); err != nil {
		return nil, err
	}
	if err := store.cleanupTemporaries(store.token, maximumTokenBytes, ".consumed-"); err != nil {
		return nil, err
	}
	closeOnError = false
	return store, nil
}

func openSecureTarget(path string) (secureTarget, error) {
	if !filepath.IsAbs(path) || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return secureTarget{}, errors.New("private file path must be absolute")
	}
	clean := filepath.Clean(path)
	directory := filepath.Dir(clean)
	fd, err := unix.Openat2(unix.AT_FDCWD, directory, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return secureTarget{}, errors.New("private file directory is unavailable")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return secureTarget{}, errors.New("private file directory is not owner-controlled")
	}
	return secureTarget{dir: os.NewFile(uintptr(fd), directory), name: filepath.Base(clean)}, nil
}

func (store *linuxStore) ReadToken() ([]byte, error) {
	return readAt(store.token, maximumTokenBytes)
}

func (store *linuxStore) ReadIdentity() (runneridentity.Document, bool, error) {
	data, err := readAt(store.identity, runneridentity.MaximumDocumentBytes)
	if errors.Is(err, os.ErrNotExist) {
		return runneridentity.Document{}, false, nil
	}
	if err != nil {
		return runneridentity.Document{}, false, err
	}
	defer clear(data)
	document, err := runneridentity.Decode(data)
	if err != nil {
		return runneridentity.Document{}, false, errors.New("runner identity document is invalid")
	}
	return document, true, nil
}

func (store *linuxStore) WriteIdentity(document runneridentity.Document) error {
	data, err := document.Encode()
	if err != nil {
		return err
	}
	defer clear(data)
	return replaceAt(store.identity, data, ".enroll-", store.hooks.afterIdentityTempSync, store.hooks.afterIdentityRename)
}

func (store *linuxStore) CredentialExists() (bool, error) {
	data, err := readAt(store.credential, 4096)
	clear(data)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (store *linuxStore) InstallCredential(credential []byte) error {
	if len(credential) == 0 || len(credential) > 4096 {
		return errors.New("issued credential is invalid")
	}
	existing, err := readAt(store.credential, 4096)
	if err == nil {
		equal := subtle.ConstantTimeCompare(existing, credential) == 1
		clear(existing)
		if !equal {
			return errors.New("credential file already contains a different credential")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := createAt(store.credential, credential, ".enroll-"); err != nil {
		return err
	}
	if store.hooks.afterCredentialSync != nil {
		if err := store.hooks.afterCredentialSync(); err != nil {
			return errors.New("credential installation interrupted after durability")
		}
	}
	return nil
}

func (store *linuxStore) RemoveToken(expected [sha256.Size]byte) error {
	data, original, err := readAtStat(store.token, maximumTokenBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	clear(data)
	if subtle.ConstantTimeCompare(digest[:], expected[:]) != 1 {
		return errors.New("registration token changed before removal")
	}
	tombstone, err := moveToTombstone(store.token, ".consumed-")
	if err != nil {
		return errors.New("isolate consumed registration token failed")
	}
	tombstoneTarget := secureTarget{dir: store.token.dir, name: tombstone}
	moved, err := statAt(tombstoneTarget, maximumTokenBytes)
	if err != nil || moved.Dev != original.Dev || moved.Ino != original.Ino {
		_ = unix.Renameat2(int(store.token.dir.Fd()), tombstone, int(store.token.dir.Fd()), store.token.name, unix.RENAME_NOREPLACE)
		return errors.New("registration token changed before removal")
	}
	if err := zeroAt(tombstoneTarget, maximumTokenBytes); err != nil {
		_ = unix.Renameat2(int(store.token.dir.Fd()), tombstone, int(store.token.dir.Fd()), store.token.name, unix.RENAME_NOREPLACE)
		return errors.New("clear registration token failed")
	}
	if err := unix.Unlinkat(int(store.token.dir.Fd()), tombstone, 0); err != nil {
		return errors.New("remove registration token failed")
	}
	if err := store.token.dir.Sync(); err != nil {
		return errors.New("registration token directory durability failed")
	}
	return nil
}

func moveToTombstone(target secureTarget, marker string) (string, error) {
	for range 16 {
		var suffix [16]byte
		if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
			return "", err
		}
		name := "." + target.name + marker + hex.EncodeToString(suffix[:])
		if err := unix.Renameat2(int(target.dir.Fd()), target.name, int(target.dir.Fd()), name, unix.RENAME_NOREPLACE); err == nil {
			return name, nil
		} else if !errors.Is(err, unix.EEXIST) {
			return "", err
		}
	}
	return "", errors.New("private tombstone identities exhausted")
}

func readAt(target secureTarget, maximum int64) ([]byte, error) {
	data, _, err := readAtStat(target, maximum)
	return data, err
}

func readAtStat(target secureTarget, maximum int64) ([]byte, unix.Stat_t, error) {
	fd, err := unix.Openat(int(target.dir.Fd()), target.name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, unix.Stat_t{}, os.ErrNotExist
		}
		return nil, unix.Stat_t{}, errors.New("open private file failed")
	}
	file := os.NewFile(uintptr(fd), target.name)
	defer file.Close()
	stat, err := checkedStat(fd, maximum)
	if err != nil || stat.Mode&0o7777 != 0o600 {
		return nil, stat, errors.New("private file must be an owner-only, singly-linked regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		clear(data)
		return nil, stat, errors.New("read private file failed")
	}
	return data, stat, nil
}

func checkedStat(fd int, maximum int64) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Size < 0 || stat.Size > maximum {
		return stat, errors.New("private file metadata is invalid")
	}
	return stat, nil
}

func createAt(target secureTarget, data []byte, marker string) error {
	name, file, err := temporaryAt(target, marker)
	if err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed {
			_ = zeroOpenFile(file, len(data))
			_ = unix.Unlinkat(int(target.dir.Fd()), name, 0)
		}
		_ = file.Close()
	}()
	if err := writeAndSync(file, data); err != nil {
		return errors.New("write private file failed")
	}
	if err := unix.Renameat2(int(target.dir.Fd()), name, int(target.dir.Fd()), target.name, unix.RENAME_NOREPLACE); err != nil {
		return errors.New("install private file failed")
	}
	installed = true
	_ = file.Close()
	if err := target.dir.Sync(); err != nil {
		return errors.New("private file directory durability failed")
	}
	return nil
}

func replaceAt(target secureTarget, data []byte, marker string, afterSync, afterRename func() error) error {
	current, original, err := readAtStat(target, runneridentity.MaximumDocumentBytes)
	clear(current)
	if errors.Is(err, os.ErrNotExist) {
		return createAt(target, data, marker)
	} else if err != nil {
		return err
	}
	name, file, err := temporaryAt(target, marker)
	if err != nil {
		return err
	}
	exchanged := false
	defer func() {
		if !exchanged {
			_ = zeroOpenFile(file, len(data))
			_ = file.Close()
			_ = unix.Unlinkat(int(target.dir.Fd()), name, 0)
			return
		}
		_ = file.Close()
	}()
	if err := writeAndSync(file, data); err != nil {
		return errors.New("write runner identity failed")
	}
	if afterSync != nil {
		if err := afterSync(); err != nil {
			return errors.New("runner identity update interrupted after temporary sync")
		}
	}
	if _, err := checkedStat(int(file.Fd()), runneridentity.MaximumDocumentBytes); err != nil {
		return errors.New("runner identity temporary file changed")
	}
	currentStat, err := statAt(target, runneridentity.MaximumDocumentBytes)
	if err != nil || currentStat.Dev != original.Dev || currentStat.Ino != original.Ino {
		return errors.New("runner identity target changed during update")
	}
	if err := unix.Renameat2(int(target.dir.Fd()), name, int(target.dir.Fd()), target.name, unix.RENAME_EXCHANGE); err != nil {
		return errors.New("atomic runner identity update failed")
	}
	exchanged = true
	if afterRename != nil {
		if err := afterRename(); err != nil {
			return errors.New("runner identity update interrupted after atomic rename")
		}
	}
	if err := zeroAt(secureTarget{dir: target.dir, name: name}, runneridentity.MaximumDocumentBytes); err != nil {
		return errors.New("clear displaced runner identity failed")
	}
	if err := unix.Unlinkat(int(target.dir.Fd()), name, 0); err != nil {
		return errors.New("remove displaced runner identity failed")
	}
	if err := target.dir.Sync(); err != nil {
		return errors.New("runner identity directory durability failed")
	}
	return nil
}

func statAt(target secureTarget, maximum int64) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(target.dir.Fd()), target.name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 || stat.Size < 0 || stat.Size > maximum {
		return stat, errors.New("private file target is unsafe")
	}
	return stat, nil
}

func temporaryAt(target secureTarget, marker string) (string, *os.File, error) {
	for range 16 {
		var suffix [16]byte
		if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
			return "", nil, errors.New("generate private temporary file name failed")
		}
		name := "." + target.name + marker + hex.EncodeToString(suffix[:])
		fd, err := unix.Openat(int(target.dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err == nil {
			return name, os.NewFile(uintptr(fd), name), nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", nil, errors.New("create private temporary file failed")
		}
	}
	return "", nil, errors.New("private temporary file identities exhausted")
}

func writeAndSync(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		data = data[written:]
	}
	return file.Sync()
}

func zeroOpenFile(file *os.File, length int) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := writeAndSync(file, make([]byte, length)); err != nil {
		return err
	}
	return nil
}

func zeroAt(target secureTarget, maximum int64) error {
	fd, err := unix.Openat(int(target.dir.Fd()), target.name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), target.name)
	defer file.Close()
	stat, err := checkedStat(fd, maximum)
	if err != nil || stat.Mode&0o7777 != 0o600 {
		return errors.New("private file cannot be safely cleared")
	}
	return zeroOpenFile(file, int(stat.Size))
}

func (store *linuxStore) cleanupTemporaries(target secureTarget, maximum int64, marker string) error {
	if _, err := target.dir.Seek(0, io.SeekStart); err != nil {
		return errors.New("inspect private file directory failed")
	}
	names, err := target.dir.Readdirnames(-1)
	if err != nil {
		return errors.New("inspect runner identity directory failed")
	}
	prefix := "." + target.name + marker
	removed := false
	for _, name := range names {
		suffix := strings.TrimPrefix(name, prefix)
		if suffix == name || len(suffix) != 32 {
			continue
		}
		if _, err := hex.DecodeString(suffix); err != nil {
			continue
		}
		temporary := secureTarget{dir: target.dir, name: name}
		if err := zeroAt(temporary, maximum); err != nil {
			return errors.New("stale private temporary is unsafe")
		}
		if err := unix.Unlinkat(int(target.dir.Fd()), name, 0); err != nil {
			return errors.New("remove stale private temporary failed")
		}
		removed = true
	}
	if removed {
		return target.dir.Sync()
	}
	return nil
}

func (store *linuxStore) Close() error {
	if store == nil {
		return nil
	}
	var failures []error
	if store.lock != nil {
		failures = append(failures, unix.Flock(int(store.lock.Fd()), unix.LOCK_UN), store.lock.Close())
	}
	seen := map[uintptr]bool{}
	for _, directory := range []*os.File{store.identity.dir, store.credential.dir, store.token.dir} {
		if directory != nil && !seen[directory.Fd()] {
			seen[directory.Fd()] = true
			failures = append(failures, directory.Close())
		}
	}
	return errors.Join(failures...)
}
