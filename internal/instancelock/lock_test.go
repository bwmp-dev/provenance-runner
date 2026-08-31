package instancelock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const helperEnvironment = "PROVENANCE_INSTANCE_LOCK_HELPER"

func TestLockIsExclusiveAcrossProcessesAndReleasedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runner.lock")
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}

	output, err := runHelper(path)
	if err == nil || !strings.Contains(string(output), ErrAlreadyHeld.Error()) {
		t.Fatalf("contending helper output/error = %q/%v", output, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	output, err = runHelper(path)
	if err != nil {
		t.Fatalf("helper after release output/error = %q/%v", output, err)
	}
}

func TestAcquireAllDeduplicatesCanonicalPathsWithoutSelfContention(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "runner.lock")
	alias := filepath.Join(root, "nested", "..", "runner.lock")
	locks, err := AcquireAll(path, path, alias)
	if err != nil {
		t.Fatalf("AcquireAll() error = %v", err)
	}
	if _, err := Acquire(path); !errors.Is(err, ErrAlreadyHeld) {
		t.Fatalf("contending Acquire() error = %v, want ErrAlreadyHeld", err)
	}
	if err := locks.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	lock, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire() after set release error = %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireAllDeduplicatesSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	aliasParent := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, aliasParent); err != nil {
		t.Skipf("create directory symlink: %v", err)
	}
	locks, err := AcquireAll(filepath.Join(root, "runner.lock"), filepath.Join(aliasParent, "runner.lock"))
	if err != nil {
		t.Fatalf("AcquireAll() error = %v", err)
	}
	if err := locks.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestAcquireAllUnwindsPartialAcquisition(t *testing.T) {
	root := t.TempDir()
	firstPath := filepath.Join(root, "a.lock")
	blockedPath := filepath.Join(root, "z.lock")
	blocker, err := Acquire(blockedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	locks, err := AcquireAll(blockedPath, firstPath)
	if locks != nil || !errors.Is(err, ErrAlreadyHeld) {
		t.Fatalf("AcquireAll() = %#v, %v; want ErrAlreadyHeld", locks, err)
	}
	first, err := Acquire(firstPath)
	if err != nil {
		t.Fatalf("first lock remained held after partial failure: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInstanceLockHelperProcess(t *testing.T) {
	path := os.Getenv(helperEnvironment)
	if path == "" {
		return
	}
	lock, err := Acquire(path)
	if err != nil {
		if errors.Is(err, ErrAlreadyHeld) {
			_, _ = os.Stderr.WriteString(err.Error())
			os.Exit(3)
		}
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func runHelper(path string) ([]byte, error) {
	command := exec.Command(os.Args[0], "-test.run=^TestInstanceLockHelperProcess$")
	command.Env = append(os.Environ(), helperEnvironment+"="+path)
	return command.CombinedOutput()
}
