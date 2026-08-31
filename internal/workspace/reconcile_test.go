package workspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagerStartupReconcilesOnlyExpiredOwnedWorkspaces(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := manager.Create(context.Background(), "expired-job")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := manager.Create(context.Background(), "fresh-job")
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-DefaultOrphanTTL - time.Minute)
	marker := filepath.Join(expired.Root(), workspaceMarkerName)
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkspaceMarker(expired.Root(), "expired-job", old); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "provenance-job-foreign")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(root); err != nil {
		t.Fatalf("restart NewManager() error = %v", err)
	}
	if _, err := os.Stat(expired.Root()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expired workspace remains: %v", err)
	}
	for _, path := range []string{fresh.Root(), foreign} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("non-expired/foreign workspace %q changed: %v", path, err)
		}
	}
	_ = fresh.Cleanup(context.Background())
	_ = os.RemoveAll(foreign)
}

func TestManagerStartupRetainsAndReportsInvalidOwnershipMarker(t *testing.T) {
	root := t.TempDir()
	invalid := filepath.Join(root, "provenance-job-invalid")
	if err := os.Mkdir(invalid, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(invalid, workspaceMarkerName), []byte(`{"version":1,"jobId":"job","createdAt":"not-a-time"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewManager(root)
	if err == nil || !strings.Contains(err.Error(), "inspect workspace") {
		t.Fatalf("NewManager() error = %v", err)
	}
	if _, statErr := os.Stat(invalid); statErr != nil {
		t.Errorf("invalid workspace was removed: %v", statErr)
	}
}
