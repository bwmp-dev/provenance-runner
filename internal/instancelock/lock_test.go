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
