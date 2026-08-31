package workspace

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
)

var ErrWorkspaceClosed = errors.New("workspace is closed")

type Manager struct {
	root string
}

func NewManager(root string) (*Manager, error) {
	if root == "" {
		root = os.TempDir()
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("create workspace manager: resolve root: %w", err)
	}
	if err := os.MkdirAll(absoluteRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create workspace manager root: %w", err)
	}
	info, err := os.Lstat(absoluteRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect workspace manager root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("create workspace manager: root must be a directory and cannot be a symbolic link")
	}
	resolvedRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace manager root: %w", err)
	}
	absoluteRoot = resolvedRoot
	if err := os.Chmod(absoluteRoot, 0o700); err != nil {
		return nil, fmt.Errorf("restrict workspace manager root: %w", err)
	}
	info, err = os.Stat(absoluteRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect workspace manager root: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("create workspace manager: root is not a directory")
	}
	return &Manager{root: absoluteRoot}, nil
}

func (m *Manager) Create(ctx context.Context, jobID string) (*Workspace, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("create job workspace: %w", err)
	}
	if jobID == "" {
		return nil, errors.New("create job workspace: job ID is empty")
	}
	root, err := os.MkdirTemp(m.root, "provenance-job-")
	if err != nil {
		return nil, fmt.Errorf("create job workspace: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		cleanupErr := os.RemoveAll(root)
		return nil, errors.Join(fmt.Errorf("restrict job workspace: %w", err), cleanupErr)
	}
	if err := ctx.Err(); err != nil {
		cleanupErr := os.RemoveAll(root)
		return nil, errors.Join(fmt.Errorf("create job workspace: %w", err), cleanupErr)
	}
	return &Workspace{managerRoot: m.root, root: root}, nil
}

type Workspace struct {
	mu          sync.Mutex
	managerRoot string
	root        string
	closed      bool
	cleaned     bool
}

func (w *Workspace) Root() string {
	return w.root
}

func (w *Workspace) WriteFile(ctx context.Context, relativePath string, content []byte, mode os.FileMode) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return "", ErrWorkspaceClosed
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("write workspace file: %w", err)
	}
	cleanedPath, err := cleanRelativePath(relativePath)
	if err != nil {
		return "", fmt.Errorf("write workspace file: %w", err)
	}
	if mode.Perm()&0o022 != 0 || mode.Perm()&^0o755 != 0 {
		return "", errors.New("write workspace file: mode is not permitted")
	}
	destination := filepath.Join(w.root, cleanedPath)
	if err := ensureDescendant(w.root, destination); err != nil {
		return "", fmt.Errorf("write workspace file: %w", err)
	}
	if _, err := os.Lstat(destination); err == nil {
		return "", fmt.Errorf("write workspace file: destination %q already exists", relativePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("write workspace file: inspect destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return "", fmt.Errorf("write workspace file: create destination directory: %w", err)
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return "", fmt.Errorf("write workspace file: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		return "", errors.Join(fmt.Errorf("write workspace file: %w", err), file.Close(), os.Remove(destination))
	}
	if err := file.Sync(); err != nil {
		return "", errors.Join(fmt.Errorf("sync workspace file: %w", err), file.Close(), os.Remove(destination))
	}
	if err := file.Close(); err != nil {
		return "", errors.Join(fmt.Errorf("close workspace file: %w", err), os.Remove(destination))
	}
	return destination, nil
}

func (w *Workspace) MakeSandboxReadable(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrWorkspaceClosed
	}
	return filepath.WalkDir(w.root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("make workspace sandbox-readable: %q is not a regular file", path)
		}
		mode := os.FileMode(0o444)
		if info.Mode().Perm()&0o111 != 0 {
			mode = 0o555
		}
		return os.Chmod(path, mode)
	})
}

func (w *Workspace) Materialize(ctx context.Context, relativePath string, entry *artifact.Entry) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return "", ErrWorkspaceClosed
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("materialize artifact: %w", err)
	}
	if entry == nil {
		return "", errors.New("materialize artifact: cache entry is nil")
	}
	cleanedPath, err := cleanRelativePath(relativePath)
	if err != nil {
		return "", fmt.Errorf("materialize artifact: %w", err)
	}
	destination := filepath.Join(w.root, cleanedPath)
	if err := ensureDescendant(w.root, destination); err != nil {
		return "", fmt.Errorf("materialize artifact: %w", err)
	}
	if _, err := os.Lstat(destination); err == nil {
		return "", fmt.Errorf("materialize artifact: destination %q already exists", relativePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("materialize artifact: inspect destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return "", fmt.Errorf("materialize artifact: create destination directory: %w", err)
	}

	reader, err := entry.Open(ctx)
	if err != nil {
		return "", fmt.Errorf("materialize artifact: %w", err)
	}
	defer reader.Close()
	temporaryFile, err := os.CreateTemp(filepath.Dir(destination), ".materialize-*")
	if err != nil {
		return "", fmt.Errorf("materialize artifact: create temporary file: %w", err)
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(temporaryFile, hasher), &contextReader{ctx: ctx, reader: reader}); err != nil {
		temporaryFile.Close()
		return "", fmt.Errorf("materialize artifact: copy cache entry: %w", err)
	}
	var copiedDigest artifact.Digest
	copy(copiedDigest[:], hasher.Sum(nil))
	if copiedDigest != entry.Digest() {
		temporaryFile.Close()
		return "", fmt.Errorf("materialize artifact: %w while copying %s", artifact.ErrCacheCorrupt, entry.CacheKey())
	}
	if err := temporaryFile.Sync(); err != nil {
		temporaryFile.Close()
		return "", fmt.Errorf("materialize artifact: sync temporary file: %w", err)
	}
	if err := temporaryFile.Close(); err != nil {
		return "", fmt.Errorf("materialize artifact: close temporary file: %w", err)
	}
	if err := os.Link(temporaryPath, destination); err != nil {
		return "", fmt.Errorf("materialize artifact: publish file: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		removeErr := os.Remove(destination)
		return "", errors.Join(fmt.Errorf("materialize artifact: remove temporary link: %w", err), removeErr)
	}
	if err := os.Chmod(destination, 0o444); err != nil {
		removeErr := os.Remove(destination)
		return "", errors.Join(fmt.Errorf("materialize artifact: make published file read-only: %w", err), removeErr)
	}
	return destination, nil
}

func (w *Workspace) Cleanup(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cleaned {
		return nil
	}
	w.closed = true
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("clean up workspace: %w", err)
	}
	if err := ensureDescendant(w.managerRoot, w.root); err != nil {
		return fmt.Errorf("clean up workspace: %w", err)
	}
	if err := os.RemoveAll(w.root); err != nil {
		return fmt.Errorf("clean up workspace: %w", err)
	}
	w.cleaned = true
	return nil
}

func cleanRelativePath(path string) (string, error) {
	if path == "" || strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`) || filepath.IsAbs(path) || filepath.VolumeName(path) != "" {
		return "", errors.New("path must be relative")
	}
	cleaned := filepath.Clean(filepath.FromSlash(path))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", errors.New("path must stay within the workspace")
	}
	return cleaned, nil
}

func ensureDescendant(root, candidate string) error {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return fmt.Errorf("resolve path relative to root: %w", err)
	}
	if relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("path is outside the configured root")
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
