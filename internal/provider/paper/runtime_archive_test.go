package paper

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
	"github.com/bwmp-dev/provenance-runner/internal/workspace"
)

func TestPreparedRuntimeArchiveIsDeterministicAndMaterializes(t *testing.T) {
	root := preparedRuntimeFixture(t)
	var first bytes.Buffer
	firstMetadata, err := WritePreparedRuntimeArchive(context.Background(), root, &first)
	if err != nil {
		t.Fatalf("WritePreparedRuntimeArchive(first) error = %v", err)
	}
	changedTime := time.Unix(1_900_000_000, 0)
	if err := filepath.Walk(root, func(path string, _ os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return os.Chtimes(path, changedTime, changedTime)
	}); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	secondMetadata, err := WritePreparedRuntimeArchive(context.Background(), root, &second)
	if err != nil {
		t.Fatalf("WritePreparedRuntimeArchive(second) error = %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) || firstMetadata != secondMetadata {
		t.Fatalf("archive changed across identical builds: first=%#v second=%#v", firstMetadata, secondMetadata)
	}
	if firstMetadata.SizeBytes != int64(first.Len()) || firstMetadata.SHA256 != artifact.SHA256(first.Bytes()).String() {
		t.Fatalf("metadata = %#v, archive bytes = %d", firstMetadata, first.Len())
	}
	wantExpanded := int64(len("mojang") + len("library") + len("patched"))
	if firstMetadata.MaximumExpandedBytes != wantExpanded {
		t.Fatalf("maximum expanded bytes = %d, want %d", firstMetadata.MaximumExpandedBytes, wantExpanded)
	}

	entry := cacheBytes(t, first.Bytes())
	manager, err := workspace.NewManager(filepath.Join(t.TempDir(), "workspaces"))
	if err != nil {
		t.Fatal(err)
	}
	jobWorkspace, err := manager.Create(context.Background(), "runtime-builder")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jobWorkspace.Cleanup(context.Background()) })
	serverRoot, err := jobWorkspace.ExtractTarGzipBounded(context.Background(), "server", entry, firstMetadata.MaximumExpandedBytes)
	if err != nil {
		t.Fatalf("ExtractTarGzipBounded() error = %v", err)
	}
	assertRuntimeFile(t, filepath.Join(serverRoot, filepath.FromSlash(alphaMojangServerPath)), "mojang")
	assertRuntimeFile(t, filepath.Join(serverRoot, filepath.FromSlash(alphaPatchedPaperPath)), "patched")
	assertRuntimeFile(t, filepath.Join(serverRoot, "libraries", "example", "library.jar"), "library")
	if _, err := os.Stat(filepath.Join(serverRoot, "plugins", "untrusted.jar")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("untrusted source path was archived: %v", err)
	}

	target := cacheBytes(t, []byte("paper overlay"))
	if _, err := jobWorkspace.Materialize(context.Background(), "server/paper.jar", target); err != nil {
		t.Fatalf("Materialize(paper.jar) error = %v", err)
	}
	if _, err := jobWorkspace.WriteFile(context.Background(), "server/eula.txt", []byte("eula=true\n"), 0o400); err != nil {
		t.Fatalf("WriteFile(eula.txt) error = %v", err)
	}
	assertRuntimeFile(t, filepath.Join(serverRoot, "paper.jar"), "paper overlay")
}

func TestPreparedRuntimeArchiveExpandedBoundIsExact(t *testing.T) {
	var output bytes.Buffer
	metadata, err := WritePreparedRuntimeArchive(context.Background(), preparedRuntimeFixture(t), &output)
	if err != nil {
		t.Fatal(err)
	}
	entry := cacheBytes(t, output.Bytes())
	manager, err := workspace.NewManager(filepath.Join(t.TempDir(), "workspaces"))
	if err != nil {
		t.Fatal(err)
	}
	jobWorkspace, err := manager.Create(context.Background(), "runtime-bound")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jobWorkspace.Cleanup(context.Background()) })
	if _, err := jobWorkspace.ExtractTarGzipBounded(context.Background(), "server", entry, metadata.MaximumExpandedBytes-1); err == nil {
		t.Fatal("ExtractTarGzipBounded() below the reported bound succeeded")
	}
	if _, err := os.Stat(filepath.Join(jobWorkspace.Root(), "server")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed extraction published a destination: %v", err)
	}
}

func TestPreparedRuntimeArchiveRequiresCompletePaperclipOutput(t *testing.T) {
	root := preparedRuntimeFixture(t)
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(alphaPatchedPaperPath))); err != nil {
		t.Fatal(err)
	}
	if _, err := WritePreparedRuntimeArchive(context.Background(), root, &bytes.Buffer{}); err == nil {
		t.Fatal("WritePreparedRuntimeArchive() without patched Paper output succeeded")
	}
}

func preparedRuntimeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		alphaMojangServerPath:           "mojang",
		"libraries/example/library.jar": "library",
		alphaPatchedPaperPath:           "patched",
		"plugins/untrusted.jar":         "must not be archived",
		"paper.jar":                     "must not be archived",
		"provenance-test-plan.json":     "must not be archived",
	}
	for _, name := range preparedRuntimeRoots {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range files {
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func cacheBytes(t *testing.T, content []byte) *artifact.Entry {
	t.Helper()
	cache, err := artifact.NewCache(t.TempDir(), artifact.CacheOptions{MaximumEntryBytes: 1 << 20, MaximumTotalBytes: 2 << 20})
	if err != nil {
		t.Fatal(err)
	}
	digest := artifact.SHA256(content)
	entry, err := cache.AcquireExact(context.Background(), digest, int64(len(content)), artifact.SourceFunc(func(_ context.Context, destination io.Writer) error {
		_, err := destination.Write(content)
		return err
	}))
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func assertRuntimeFile(t *testing.T, path, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	if string(content) != want {
		t.Fatalf("ReadFile(%q) = %q, want %q", path, content, want)
	}
}
