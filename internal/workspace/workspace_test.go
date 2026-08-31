package workspace

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
)

func TestWorkspaceWritesOwnedConfigurationFile(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	jobWorkspace, err := manager.Create(context.Background(), "job")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jobWorkspace.Cleanup(context.Background()) })
	path, err := jobWorkspace.WriteFile(context.Background(), "server/eula.txt", []byte("eula=true\n"), 0o400)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "eula=true\n" {
		t.Fatalf("ReadFile() = %q, %v", content, err)
	}
	if _, err := jobWorkspace.WriteFile(context.Background(), "server/eula.txt", nil, 0o400); err == nil {
		t.Error("duplicate WriteFile() error = nil")
	}
	if _, err := jobWorkspace.WriteFile(context.Background(), "../escape", nil, 0o400); err == nil {
		t.Error("escaping WriteFile() error = nil")
	}
	if _, err := jobWorkspace.WriteFile(context.Background(), "server/writable", nil, 0o666); err == nil {
		t.Error("group/world-writable WriteFile() error = nil")
	}
}

func TestWorkspaceMakesInputsReadableWithoutOpeningManagerRoot(t *testing.T) {
	managerRoot := t.TempDir()
	manager, err := NewManager(managerRoot)
	if err != nil {
		t.Fatal(err)
	}
	jobWorkspace, err := manager.Create(context.Background(), "job")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jobWorkspace.Cleanup(context.Background()) })
	path, err := jobWorkspace.WriteFile(context.Background(), "server/input.json", []byte("{}"), 0o400)
	if err != nil {
		t.Fatal(err)
	}
	if err := jobWorkspace.MakeSandboxReadable(context.Background()); err != nil {
		t.Fatalf("MakeSandboxReadable() error = %v", err)
	}
	managerInfo, err := os.Stat(managerRoot)
	if err != nil {
		t.Fatal(err)
	}
	workspaceInfo, err := os.Stat(jobWorkspace.Root())
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if managerInfo.Mode().Perm() != 0o700 || workspaceInfo.Mode().Perm() != 0o755 || fileInfo.Mode().Perm() != 0o444 {
			t.Errorf("modes = manager %o, workspace %o, file %o", managerInfo.Mode().Perm(), workspaceInfo.Mode().Perm(), fileInfo.Mode().Perm())
		}
	}
}

func TestWorkspaceManagerRejectsSymlinkRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symbolic links requires optional Windows privileges")
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(link); err == nil {
		t.Fatal("NewManager() error = nil")
	}
}

func TestWorkspaceManagerUsesDedicatedDefaultRoot(t *testing.T) {
	manager, err := NewManager("")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(manager.root) == filepath.Clean(os.TempDir()) {
		t.Fatal("default workspace manager root is the shared temporary directory")
	}
	info, err := os.Stat(manager.root)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("default manager mode = %o, want 700", info.Mode().Perm())
	}
}

func TestWorkspaceExtractsVerifiedRuntimeArchive(t *testing.T) {
	archive := tarGzip(t, []tarEntry{
		{name: "runtime/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "runtime/bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "runtime/bin/java", mode: 0o755, content: []byte("java")},
	})
	entry := cachedEntry(t, archive)
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	jobWorkspace, err := manager.Create(context.Background(), "job")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jobWorkspace.Cleanup(context.Background()) })
	root, err := jobWorkspace.ExtractTarGzip(context.Background(), "java", entry)
	if err != nil {
		t.Fatalf("ExtractTarGzip() error = %v", err)
	}
	content, err := os.ReadFile(filepath.Join(root, "runtime", "bin", "java"))
	if err != nil || string(content) != "java" {
		t.Fatalf("extracted java = %q, %v", content, err)
	}
}

func TestWorkspaceArchiveRejectsTraversalAndSpecialFiles(t *testing.T) {
	for name, entries := range map[string][]tarEntry{
		"parent traversal": {{name: "../escape", content: []byte("bad")}},
		"absolute path":    {{name: "/escape", content: []byte("bad")}},
		"device":           {{name: "device", typeflag: tar.TypeChar}},
		"escaping symlink": {{name: "link", typeflag: tar.TypeSymlink, linkname: "../escape"}},
	} {
		t.Run(name, func(t *testing.T) {
			entry := cachedEntry(t, tarGzip(t, entries))
			manager, err := NewManager(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			jobWorkspace, err := manager.Create(context.Background(), "job")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = jobWorkspace.Cleanup(context.Background()) })
			if _, err := jobWorkspace.ExtractTarGzip(context.Background(), "java", entry); err == nil {
				t.Fatal("ExtractTarGzip() error = nil")
			}
		})
	}
}

type tarEntry struct {
	name     string
	typeflag byte
	mode     int64
	linkname string
	content  []byte
}

func tarGzip(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		mode := entry.mode
		if mode == 0 {
			mode = 0o600
		}
		header := &tar.Header{Name: entry.name, Typeflag: typeflag, Mode: mode, Linkname: entry.linkname, Size: int64(len(entry.content))}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(entry.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

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
