//go:build linux

package gatewayclient

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func newCredentialStoreTest(t *testing.T, initial []byte) (string, *linuxCredentialStore) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "credential")
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := openDurableCredentialStore(path)
	if err != nil {
		t.Fatal(err)
	}
	store := opened.(*linuxCredentialStore)
	t.Cleanup(func() { _ = store.Close() })
	return path, store
}

func TestCredentialStoreAtomicallyReplacesOwnerOnlyFileAndCleansDisplacedSecret(t *testing.T) {
	oldCredential := []byte("old credential")
	newCredential := []byte("new credential")
	path, store := newCredentialStoreTest(t, oldCredential)
	var displaced *os.File
	store.hooks.afterExchange = func(name string) error {
		var err error
		displaced, err = os.Open(filepath.Join(filepath.Dir(path), name))
		return err
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Replace(newCredential); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, newCredential) || after.Mode().Perm() != 0o600 || os.SameFile(before, after) {
		t.Fatalf("replacement data=%q mode=%o same=%t err=%v", data, after.Mode().Perm(), os.SameFile(before, after), err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("credential directory retained temporary files: %v", entries)
	}
	if displaced == nil {
		t.Fatal("displaced credential was not observed")
	}
	defer displaced.Close()
	cleared, err := io.ReadAll(displaced)
	if err != nil || !bytes.Equal(cleared, make([]byte, len(oldCredential))) {
		t.Fatalf("displaced credential retained secret bytes: %x, %v", cleared, err)
	}
	if err := store.Replace(newCredential); err != nil {
		t.Fatalf("exact durable replay failed: %v", err)
	}
}

func TestCredentialStoreRestartClearsAndRemovesStaleSecretTemporary(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "credential")
	if err := os.WriteFile(path, []byte("current credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	stalePath := filepath.Join(directory, ".credential.rotation-00112233445566778899aabbccddeeff")
	staleSecret := []byte("stale secret")
	if err := os.WriteFile(stalePath, staleSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	stale, err := os.Open(stalePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stale.Close()
	store, err := openDurableCredentialStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := os.Stat(stalePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temporary still exists: %v", err)
	}
	cleared, err := os.ReadFile(stale.Name())
	if err == nil {
		t.Fatal("unlinked stale temporary unexpectedly remained path-readable")
	}
	if _, err := stale.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	cleared = make([]byte, len(staleSecret))
	if _, err := stale.Read(cleared); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cleared, make([]byte, len(cleared))) {
		t.Fatalf("stale temporary retained secret bytes: %x", cleared)
	}
}

func TestCredentialStorePreservesLastCredentialAcrossInjectedCrashBoundaries(t *testing.T) {
	oldCredential := []byte("old credential")
	newCredential := []byte("new credential")
	for name, configure := range map[string]func(*linuxCredentialStore){
		"before write": func(store *linuxCredentialStore) {
			store.hooks.beforeWrite = func() error { return errors.New("crash") }
		},
		"after temporary sync": func(store *linuxCredentialStore) {
			store.hooks.afterTempSync = func(string) error { return errors.New("crash") }
		},
	} {
		t.Run(name, func(t *testing.T) {
			path, store := newCredentialStoreTest(t, oldCredential)
			configure(store)
			if err := store.Replace(newCredential); err == nil || strings.Contains(err.Error(), string(newCredential)) {
				t.Fatalf("replacement result = %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, oldCredential) {
				t.Fatalf("last credential = %q, %v", data, err)
			}
		})
	}

	t.Run("after atomic exchange", func(t *testing.T) {
		path, store := newCredentialStoreTest(t, oldCredential)
		store.hooks.afterExchange = func(string) error { return errors.New("crash") }
		if err := store.Replace(newCredential); err == nil {
			t.Fatal("injected crash was ignored")
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, newCredential) {
			t.Fatalf("atomically installed credential = %q, %v", data, err)
		}
		_ = store.Close()
		reopened, err := openDurableCredentialStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		entries, _ := os.ReadDir(filepath.Dir(path))
		if len(entries) != 1 {
			t.Fatalf("restart did not remove crash temporary: %v", entries)
		}
		if err := reopened.Replace(newCredential); err != nil {
			t.Fatalf("restart durability confirmation = %v", err)
		}
	})

	t.Run("after directory sync", func(t *testing.T) {
		path, store := newCredentialStoreTest(t, oldCredential)
		store.hooks.afterDirSync = func() error { return errors.New("crash") }
		if err := store.Replace(newCredential); err == nil {
			t.Fatal("injected post-sync crash was ignored")
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, newCredential) {
			t.Fatalf("directory-synced credential = %q, %v", data, err)
		}
	})
}

func TestCredentialStoreRejectsSymlinkHardlinkModesAndPathReplacement(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if store, err := openDurableCredentialStore(symlink); err == nil || store != nil {
		t.Fatal("symbolic-link credential target was accepted")
	}
	directoryLink := filepath.Join(t.TempDir(), "linked-directory")
	if err := os.Symlink(directory, directoryLink); err != nil {
		t.Fatal(err)
	}
	if store, err := openDurableCredentialStore(filepath.Join(directoryLink, "target")); err == nil || store != nil {
		t.Fatal("symbolic-link credential directory was accepted")
	}
	hardlink := filepath.Join(directory, "hardlink")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if store, err := openDurableCredentialStore(target); err == nil || store != nil {
		t.Fatal("multiply-linked credential target was accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatal(err)
	}
	if store, err := openDurableCredentialStore(target); err == nil || store != nil {
		t.Fatal("group-readable credential target was accepted")
	}
	if err := os.Chmod(target, 0o400); err != nil {
		t.Fatal(err)
	}
	if store, err := openDurableCredentialStore(target); err == nil || store != nil {
		t.Fatal("owner-read-only credential target advertised replacement capability")
	}
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := openDurableCredentialStore(target)
	if err != nil {
		t.Fatal(err)
	}
	store := opened.(*linuxCredentialStore)
	defer store.Close()
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(replacement, []byte("attacker replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, target); err != nil {
		t.Fatal(err)
	}
	if err := store.Replace([]byte("new credential")); err == nil {
		t.Fatal("replaced target inode was accepted")
	}
}

func TestCredentialStoreDetectsTemporaryHardlinkRaceWithoutReplacingTarget(t *testing.T) {
	oldCredential := []byte("old credential")
	path, store := newCredentialStoreTest(t, oldCredential)
	var hostileLink string
	store.hooks.afterTempSync = func(name string) error {
		hostileLink = filepath.Join(filepath.Dir(path), "hostile-link")
		return unix.Linkat(int(store.dir.Fd()), name, unix.AT_FDCWD, hostileLink, 0)
	}
	if err := store.Replace([]byte("new credential")); err == nil {
		t.Fatal("temporary hardlink race was accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, oldCredential) {
		t.Fatalf("last credential changed: %q, %v", data, err)
	}
	linked, err := os.ReadFile(hostileLink)
	if err != nil || !bytes.Equal(linked, make([]byte, len(linked))) {
		t.Fatalf("hardlinked temporary retained secret bytes: %x, %v", linked, err)
	}
}
