package workspace

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
)

const (
	MaximumArchiveEntries = 100_000
	MaximumExpandedBytes  = int64(1 << 30)
)

type pendingLink struct {
	path     string
	target   string
	typeflag byte
}

func (w *Workspace) ExtractTarGzip(ctx context.Context, relativePath string, entry *artifact.Entry) (string, error) {
	return w.ExtractTarGzipBounded(ctx, relativePath, entry, MaximumExpandedBytes)
}

func (w *Workspace) ExtractTarGzipBounded(ctx context.Context, relativePath string, entry *artifact.Entry, maximumExpanded int64) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return "", ErrWorkspaceClosed
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("extract archive: %w", err)
	}
	if entry == nil {
		return "", errors.New("extract archive: cache entry is nil")
	}
	if maximumExpanded <= 0 || maximumExpanded > MaximumExpandedBytes {
		return "", fmt.Errorf("extract archive: expanded size limit must be between 1 and %d", MaximumExpandedBytes)
	}
	cleanedPath, err := cleanRelativePath(relativePath)
	if err != nil {
		return "", fmt.Errorf("extract archive: %w", err)
	}
	destination := filepath.Join(w.root, cleanedPath)
	if err := ensureDescendant(w.root, destination); err != nil {
		return "", fmt.Errorf("extract archive: %w", err)
	}
	if _, err := os.Lstat(destination); err == nil {
		return "", fmt.Errorf("extract archive: destination %q already exists", relativePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("extract archive: inspect destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return "", fmt.Errorf("extract archive: create parent: %w", err)
	}
	temporary, err := os.MkdirTemp(filepath.Dir(destination), ".extract-*")
	if err != nil {
		return "", fmt.Errorf("extract archive: create temporary directory: %w", err)
	}
	defer os.RemoveAll(temporary)

	reader, err := entry.Open(ctx)
	if err != nil {
		return "", fmt.Errorf("extract archive: %w", err)
	}
	defer reader.Close()
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return "", fmt.Errorf("extract archive: open gzip stream: %w", err)
	}
	defer gzipReader.Close()

	links := make([]pendingLink, 0)
	archive := tar.NewReader(gzipReader)
	var entries int
	var expanded int64
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("extract archive: read tar entry: %w", err)
		}
		entries++
		if entries > MaximumArchiveEntries {
			return "", errors.New("extract archive: entry limit exceeded")
		}
		path, err := archivePath(temporary, header.Name)
		if err != nil {
			return "", fmt.Errorf("extract archive entry %q: %w", header.Name, err)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o700); err != nil {
				return "", fmt.Errorf("extract archive directory: %w", err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maximumExpanded-expanded {
				return "", errors.New("extract archive: expanded size limit exceeded")
			}
			expanded += header.Size
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return "", fmt.Errorf("extract archive: create file parent: %w", err)
			}
			mode := os.FileMode(0o400)
			if header.FileInfo().Mode()&0o111 != 0 {
				mode = 0o500
			}
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return "", fmt.Errorf("extract archive file: %w", err)
			}
			_, copyErr := io.CopyN(file, &contextReader{ctx: ctx, reader: archive}, header.Size)
			closeErr := file.Close()
			if copyErr != nil {
				return "", errors.Join(fmt.Errorf("extract archive file: %w", copyErr), closeErr)
			}
			if closeErr != nil {
				return "", fmt.Errorf("extract archive file: %w", closeErr)
			}
		case tar.TypeSymlink, tar.TypeLink:
			links = append(links, pendingLink{path: path, target: header.Linkname, typeflag: header.Typeflag})
		default:
			return "", fmt.Errorf("extract archive: unsupported tar entry type %d", header.Typeflag)
		}
	}
	for _, link := range links {
		if err := materializeArchiveLink(temporary, link); err != nil {
			return "", fmt.Errorf("extract archive link: %w", err)
		}
	}
	if err := os.Rename(temporary, destination); err != nil {
		return "", fmt.Errorf("extract archive: publish directory: %w", err)
	}
	return destination, nil
}

func archivePath(root, name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, `\`) || strings.HasPrefix(name, "/") {
		return "", errors.New("path is not a safe relative POSIX path")
	}
	cleaned := filepath.FromSlash(name)
	if filepath.VolumeName(cleaned) != "" {
		return "", errors.New("path has a volume name")
	}
	cleaned = filepath.Clean(cleaned)
	if cleaned == "." {
		return "", errors.New("path is empty")
	}
	path := filepath.Join(root, cleaned)
	if err := ensureDescendant(root, path); err != nil {
		return "", err
	}
	return path, nil
}

func materializeArchiveLink(root string, link pendingLink) error {
	if link.target == "" || strings.ContainsRune(link.target, '\x00') || strings.Contains(link.target, `\`) || strings.HasPrefix(link.target, "/") {
		return errors.New("link target is not a safe relative POSIX path")
	}
	var target string
	if link.typeflag == tar.TypeLink {
		var err error
		target, err = archivePath(root, link.target)
		if err != nil {
			return err
		}
	} else {
		target = filepath.Clean(filepath.Join(filepath.Dir(link.path), filepath.FromSlash(link.target)))
		if err := ensureDescendant(root, target); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(link.path), 0o700); err != nil {
		return err
	}
	if link.typeflag == tar.TypeLink {
		return os.Link(target, link.path)
	}
	relativeTarget, err := filepath.Rel(filepath.Dir(link.path), target)
	if err != nil {
		return err
	}
	return os.Symlink(relativeTarget, link.path)
}
