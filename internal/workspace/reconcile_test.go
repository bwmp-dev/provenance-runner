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

func TestReconcileOwnedAttemptsImmediatelyRemovesOnlyValidOwnedWorkspaces(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := manager.Create(context.Background(), "attempt-1")
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "provenance-job-foreign")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(root, "operator-data")
	if err := os.Mkdir(unrelated, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := manager.ReconcileOwnedAttempts(context.Background()); err != nil {
		t.Fatalf("ReconcileOwnedAttempts() error = %v", err)
	}
	if _, err := os.Stat(owned.Root()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned workspace remains: %v", err)
	}
	for _, path := range []string{foreign, unrelated} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("foreign path %q changed: %v", path, err)
		}
	}
}

func TestReconcileOwnedAttemptsFailsClosedOnAmbiguousMarker(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(root, "provenance-job-invalid")
	if err := os.Mkdir(invalid, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(invalid, workspaceMarkerName), []byte(`{"version":1,"jobId":"attempt","createdAt":"invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err = manager.ReconcileOwnedAttempts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("ReconcileOwnedAttempts() error = %v", err)
	}
	if _, statErr := os.Stat(invalid); statErr != nil {
		t.Fatalf("ambiguous workspace was removed: %v", statErr)
	}
}

func TestReconcilePreservesWorkspaceCreatedAfterSweepCutoff(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().UTC().Add(-time.Second)
	owned, err := manager.Create(context.Background(), "concurrent-new-attempt")
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Cleanup(context.Background())
	if err := manager.Reconcile(context.Background(), cutoff); err != nil {
		t.Fatalf("fresh workspace created during sweep refused: %v", err)
	}
	if _, err := os.Stat(owned.Root()); err != nil {
		t.Fatal("fresh workspace removed")
	}
}

func TestReconcileStillRefusesFutureDatedOwnership(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(manager.root, "provenance-job-future")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkspaceMarker(root, "future", time.Now().UTC().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reconcile(context.Background(), time.Now().UTC()); err == nil {
		t.Fatal("future ownership accepted")
	}
	if err := manager.ReconcileOwnedAttempts(context.Background()); err == nil {
		t.Fatal("future ownership accepted for deletion")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal("ambiguous ownership removed")
	}
}
