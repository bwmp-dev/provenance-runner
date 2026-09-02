//go:build linux

package enrollment

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/runneridentity"
)

func newStoreTest(t *testing.T) (testPaths, *linuxStore, runneridentity.Document) {
	t.Helper()
	paths := setupEnrollment(t, "https://api.example.test", testToken)
	opened, err := openStore(paths.identity, paths.credential, paths.token)
	if err != nil {
		t.Fatal(err)
	}
	store := opened.(*linuxStore)
	t.Cleanup(func() { _ = store.Close() })
	tokenHash := sha256.Sum256([]byte(testToken))
	document, err := runneridentity.NewPrepared(testOrganizationID, testRunnerID, tokenHash, "enrollment-store-test", 900, strings.NewReader(strings.Repeat("q", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return paths, store, document
}

func TestStoreRejectsUnsafeTokenAndIdentityTargets(t *testing.T) {
	t.Run("world readable token", func(t *testing.T) {
		paths := setupEnrollment(t, "https://api.example.test", testToken)
		if err := os.Chmod(paths.token, 0o644); err != nil {
			t.Fatal(err)
		}
		store, err := openStore(paths.identity, paths.credential, paths.token)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if _, err := store.ReadToken(); err == nil {
			t.Fatal("world-readable token was accepted")
		}
	})

	t.Run("hard linked token", func(t *testing.T) {
		paths := setupEnrollment(t, "https://api.example.test", testToken)
		if err := os.Link(paths.token, filepath.Join(paths.directory, "token-copy")); err != nil {
			t.Fatal(err)
		}
		store, err := openStore(paths.identity, paths.credential, paths.token)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if _, err := store.ReadToken(); err == nil {
			t.Fatal("hard-linked token was accepted")
		}
	})

	t.Run("symbolic identity", func(t *testing.T) {
		paths := setupEnrollment(t, "https://api.example.test", testToken)
		target := filepath.Join(paths.directory, "target")
		if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, paths.identity); err != nil {
			t.Fatal(err)
		}
		store, err := openStore(paths.identity, paths.credential, paths.token)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if _, _, err := store.ReadIdentity(); err == nil {
			t.Fatal("symbolic-link identity was accepted")
		}
	})

	t.Run("symbolic directory", func(t *testing.T) {
		paths := setupEnrollment(t, "https://api.example.test", testToken)
		linkParent := filepath.Join(t.TempDir(), "linked")
		if err := os.Symlink(paths.directory, linkParent); err != nil {
			t.Fatal(err)
		}
		if store, err := openStore(filepath.Join(linkParent, "identity.json"), paths.credential, paths.token); err == nil || store != nil {
			t.Fatal("symbolic-link directory was accepted")
		}
	})
}

func TestStoreExcludesConcurrentEnrollment(t *testing.T) {
	paths, _, _ := newStoreTest(t)
	if second, err := openStore(paths.identity, paths.credential, paths.token); err == nil || second != nil {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("concurrent enrollment acquired the same lock")
	}
}

func TestStoreIdentityCrashBoundariesAreRecoverableAndClearStaleSecrets(t *testing.T) {
	paths, store, prepared := newStoreTest(t)
	if err := store.WriteIdentity(prepared); err != nil {
		t.Fatal(err)
	}
	terminal, err := prepared.Terminated("credential_not_replayable")
	if err != nil {
		t.Fatal(err)
	}

	store.hooks.afterIdentityTempSync = func() error { return errors.New("crash") }
	if err := store.WriteIdentity(terminal); err == nil {
		t.Fatal("temporary-sync crash hook was ignored")
	}
	document, exists, err := store.ReadIdentity()
	if err != nil || !exists || document.Phase != runneridentity.PhasePrepared {
		t.Fatalf("pre-rename identity = %#v, %t, %v", document, exists, err)
	}
	store.hooks.afterIdentityTempSync = nil
	var displacedName string
	store.hooks.afterIdentityRename = func() error {
		entries, _ := os.ReadDir(paths.directory)
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".identity.json.enroll-") {
				displacedName = entry.Name()
			}
		}
		return errors.New("crash")
	}
	if err := store.WriteIdentity(terminal); err == nil {
		t.Fatal("post-rename crash hook was ignored")
	}
	document, exists, err = store.ReadIdentity()
	if err != nil || !exists || document.Phase != runneridentity.PhaseTerminal {
		t.Fatalf("post-rename identity = %#v, %t, %v", document, exists, err)
	}
	if displacedName == "" {
		t.Fatal("displaced secret document was not retained at simulated crash")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(paths.identity, paths.credential, paths.token)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := os.Stat(filepath.Join(paths.directory, displacedName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restart retained displaced secret document: %v", err)
	}
}

func TestStoreCredentialInstallIsCreateOnlyAndRestartIdempotent(t *testing.T) {
	paths, store, _ := newStoreTest(t)
	credential := []byte(credentialFor(33))
	store.hooks.afterCredentialSync = func() error { return errors.New("crash") }
	if err := store.InstallCredential(credential); err == nil {
		t.Fatal("post-durability crash hook was ignored")
	}
	installed, err := os.ReadFile(paths.credential)
	if err != nil || !bytes.Equal(installed, credential) || fileMode(t, paths.credential) != 0o600 {
		t.Fatalf("durable credential = %q mode=%o err=%v", installed, fileMode(t, paths.credential), err)
	}
	store.hooks.afterCredentialSync = nil
	if err := store.InstallCredential(credential); err != nil {
		t.Fatalf("exact restart installation failed: %v", err)
	}
	if err := store.InstallCredential([]byte(credentialFor(34))); err == nil {
		t.Fatal("different existing credential was overwritten")
	}
}
