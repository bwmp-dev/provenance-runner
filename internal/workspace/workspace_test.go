package workspace

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
)

func TestWorkspaceMaterializesVerifiedArtifactAndCleansUp(t *testing.T) {
	payload := []byte("fixture jar")
	entry := cachedEntry(t, payload)
	managerRoot := t.TempDir()
	manager, err := NewManager(managerRoot)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	jobWorkspace, err := manager.Create(context.Background(), "job/test")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	workspaceRoot := jobWorkspace.Root()

	path, err := jobWorkspace.Materialize(context.Background(), "plugins/fixture.jar", entry)
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content) != string(payload) {
		t.Fatalf("content = %q, want %q", content, payload)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("materialized mode = %v, want read-only", info.Mode().Perm())
	}
	if err := ensureDescendant(managerRoot, path); err != nil {
		t.Fatalf("materialized path is outside manager root: %v", err)
	}

	if err := jobWorkspace.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if _, err := os.Stat(workspaceRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace Stat() error = %v, want not exist", err)
	}
	if err := jobWorkspace.Cleanup(context.Background()); err != nil {
		t.Fatalf("second Cleanup() error = %v", err)
	}
	if _, err := jobWorkspace.Materialize(context.Background(), "fixture.jar", entry); !errors.Is(err, ErrWorkspaceClosed) {
		t.Fatalf("Materialize() after cleanup error = %v, want ErrWorkspaceClosed", err)
	}
}

func TestWorkspaceRejectsEscapingAndDuplicatePaths(t *testing.T) {
	entry := cachedEntry(t, []byte("fixture"))
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	jobWorkspace, err := manager.Create(context.Background(), "job/test")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() {
		_ = jobWorkspace.Cleanup(context.Background())
	})

	for _, path := range []string{"", ".", "..", "../escape.jar", "/absolute.jar"} {
		t.Run(path, func(t *testing.T) {
			if _, err := jobWorkspace.Materialize(context.Background(), path, entry); err == nil {
				t.Fatalf("Materialize(%q) error = nil", path)
			}
		})
	}
	if _, err := jobWorkspace.Materialize(context.Background(), "fixture.jar", entry); err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}
	if _, err := jobWorkspace.Materialize(context.Background(), "fixture.jar", entry); err == nil {
		t.Fatal("duplicate Materialize() error = nil")
	}
}

func TestWorkspaceDoesNotPublishCorruptCacheEntry(t *testing.T) {
	payload := []byte("fixture")
	digest := artifact.SHA256(payload)
	cacheRoot := t.TempDir()
	cache, err := artifact.NewCache(cacheRoot, artifact.CacheOptions{})
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	entry, err := cache.Acquire(context.Background(), digest, source(payload))
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	corruptCacheEntry(t, cacheRoot, digest)
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	jobWorkspace, err := manager.Create(context.Background(), "job/test")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() {
		_ = jobWorkspace.Cleanup(context.Background())
	})

	destination := filepath.Join(jobWorkspace.Root(), "fixture.jar")
	if _, err := jobWorkspace.Materialize(context.Background(), "fixture.jar", entry); !errors.Is(err, artifact.ErrCacheCorrupt) {
		t.Fatalf("Materialize() error = %v, want ErrCacheCorrupt", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination Stat() error = %v, want not exist", err)
	}
}

func TestWorkspaceCleanupHonorsContextAndCanBeRetried(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	jobWorkspace, err := manager.Create(context.Background(), "job/test")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := jobWorkspace.Cleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Cleanup() error = %v, want context canceled", err)
	}
	if err := jobWorkspace.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() retry error = %v", err)
	}
}

func cachedEntry(t *testing.T, payload []byte) *artifact.Entry {
	t.Helper()
	cache, err := artifact.NewCache(t.TempDir(), artifact.CacheOptions{})
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	entry, err := cache.Acquire(context.Background(), artifact.SHA256(payload), source(payload))
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	return entry
}

func source(payload []byte) artifact.Source {
	return artifact.SourceFunc(func(_ context.Context, destination io.Writer) error {
		_, err := destination.Write(payload)
		return err
	})
}

func corruptCacheEntry(t *testing.T, root string, digest artifact.Digest) {
	t.Helper()
	encoded := digest.String()
	path := filepath.Join(root, "sha256", encoded[:2], encoded[2:])
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
