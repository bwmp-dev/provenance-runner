package gvisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const teardownTestContainerID = "provenance-0123456789abcdef0123456789abcdef"

func TestConfirmContainerTeardownWaitsForExactRuntimeAndScopeResidue(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	cgroupRoot := filepath.Join(root, "app.slice")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cgroupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	provider := &Provider{config: Config{
		StateRoot:         stateRoot,
		CgroupDriver:      CgroupDriverSystemdUser,
		SystemdCgroupRoot: cgroupRoot,
	}}
	residue := []string{
		filepath.Join(stateRoot, teardownTestContainerID+"_sandbox:"+teardownTestContainerID+".lock"),
		filepath.Join(stateRoot, "runsc-"+teardownTestContainerID+".sock"),
		systemdCgroupPath(cgroupRoot, teardownTestContainerID),
	}
	for index, path := range residue {
		if index == len(residue)-1 {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := filepath.Join(stateRoot, "runsc-provenance-ffffffffffffffffffffffffffffffff.sock")
	if err := os.WriteFile(unrelated, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	removed := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		var removeErr error
		for _, path := range residue {
			removeErr = errors.Join(removeErr, os.Remove(path))
		}
		removed <- removeErr
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := provider.confirmContainerTeardown(ctx, teardownTestContainerID); err != nil {
		t.Fatalf("confirmContainerTeardown() error = %v", err)
	}
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated sandbox state changed: %v", err)
	}
}

func TestConfirmContainerTeardownReportsPersistentExactResidue(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	cgroupRoot := filepath.Join(root, "app.slice")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cgroupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	provider := &Provider{config: Config{
		StateRoot:         stateRoot,
		CgroupDriver:      CgroupDriverSystemdUser,
		SystemdCgroupRoot: cgroupRoot,
	}}
	residue := []string{
		filepath.Join(stateRoot, teardownTestContainerID+"_sandbox:"+teardownTestContainerID+".lock"),
		filepath.Join(stateRoot, "runsc-"+teardownTestContainerID+".sock"),
		systemdCgroupPath(cgroupRoot, teardownTestContainerID),
	}
	for index, path := range residue {
		if index == len(residue)-1 {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	err := provider.confirmContainerTeardown(ctx, teardownTestContainerID)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("confirmContainerTeardown() error = %v", err)
	}
	for _, path := range residue {
		if !strings.Contains(err.Error(), path) {
			t.Errorf("confirmContainerTeardown() error %q does not identify residue %q", err, path)
		}
	}
}

func TestConfirmContainerTeardownRejectsInvalidContainerIdentity(t *testing.T) {
	provider := &Provider{}
	if err := provider.confirmContainerTeardown(context.Background(), "../../escape"); err == nil {
		t.Fatal("confirmContainerTeardown() error = nil")
	}
}
