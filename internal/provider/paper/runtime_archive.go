package paper

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/workspace"
)

var preparedRuntimeRoots = []string{"cache", "libraries", "versions"}

const (
	alphaMojangServerPath = "cache/mojang_1.21.8.jar"
	alphaPatchedPaperPath = "versions/1.21.8/paper-1.21.8.jar"
)

type PreparedRuntimeMetadata struct {
	SHA256               string `json:"sha256"`
	SizeBytes            int64  `json:"sizeBytes"`
	MaximumExpandedBytes int64  `json:"maximumExpandedBytes"`
}

type preparedRuntimeEntry struct {
	path   string
	source string
	size   int64
	isDir  bool
}

func WritePreparedRuntimeArchive(ctx context.Context, sourceRoot string, destination io.Writer) (PreparedRuntimeMetadata, error) {
	if err := ctx.Err(); err != nil {
		return PreparedRuntimeMetadata{}, fmt.Errorf("build prepared Paper runtime: %w", err)
	}
	if destination == nil {
		return PreparedRuntimeMetadata{}, errors.New("build prepared Paper runtime: destination is nil")
	}
	absoluteRoot, err := filepath.Abs(sourceRoot)
	if err != nil {
		return PreparedRuntimeMetadata{}, fmt.Errorf("build prepared Paper runtime: resolve source root: %w", err)
	}
	entries, expanded, err := collectPreparedRuntime(ctx, absoluteRoot)
	if err != nil {
		return PreparedRuntimeMetadata{}, err
	}

	hasher := sha256.New()
	counter := &countingWriter{writer: io.MultiWriter(destination, hasher)}
	gzipWriter, err := gzip.NewWriterLevel(counter, gzip.BestCompression)
	if err != nil {
		return PreparedRuntimeMetadata{}, fmt.Errorf("build prepared Paper runtime: create gzip stream: %w", err)
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	writeErr := writePreparedRuntime(ctx, tarWriter, entries)
	closeTarErr := tarWriter.Close()
	closeGzipErr := gzipWriter.Close()
	if err := errors.Join(writeErr, closeTarErr, closeGzipErr); err != nil {
		return PreparedRuntimeMetadata{}, fmt.Errorf("build prepared Paper runtime: %w", err)
	}
	return PreparedRuntimeMetadata{
		SHA256:               hex.EncodeToString(hasher.Sum(nil)),
		SizeBytes:            counter.written,
		MaximumExpandedBytes: expanded,
	}, nil
}

func collectPreparedRuntime(ctx context.Context, root string) ([]preparedRuntimeEntry, int64, error) {
	entries := make([]preparedRuntimeEntry, 0)
	found := make(map[string]bool)
	libraryFiles := 0
	var expanded int64
	for _, name := range preparedRuntimeRoots {
		rootPath := filepath.Join(root, name)
		info, err := os.Lstat(rootPath)
		if err != nil {
			return nil, 0, fmt.Errorf("build prepared Paper runtime: inspect %s: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, 0, fmt.Errorf("build prepared Paper runtime: %s must be a directory and cannot be a symbolic link", name)
		}
		err = filepath.WalkDir(rootPath, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			archivePath := filepath.ToSlash(relative)
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("symbolic link %q is not permitted", archivePath)
			}
			if info.IsDir() {
				entries = append(entries, preparedRuntimeEntry{path: archivePath + "/", source: path, isDir: true})
				if len(entries) > workspace.MaximumArchiveEntries {
					return fmt.Errorf("entry count exceeds the runner limit of %d", workspace.MaximumArchiveEntries)
				}
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("%q is not a regular file", archivePath)
			}
			if info.Size() < 0 || info.Size() > workspace.MaximumExpandedBytes-expanded {
				return errors.New("expanded size exceeds the runner archive limit")
			}
			expanded += info.Size()
			entries = append(entries, preparedRuntimeEntry{path: archivePath, source: path, size: info.Size()})
			if len(entries) > workspace.MaximumArchiveEntries {
				return fmt.Errorf("entry count exceeds the runner limit of %d", workspace.MaximumArchiveEntries)
			}
			found[archivePath] = true
			if strings.HasPrefix(archivePath, "libraries/") {
				libraryFiles++
			}
			return nil
		})
		if err != nil {
			return nil, 0, fmt.Errorf("build prepared Paper runtime: inspect %s: %w", name, err)
		}
	}
	if !found[alphaMojangServerPath] {
		return nil, 0, fmt.Errorf("build prepared Paper runtime: %s is missing", alphaMojangServerPath)
	}
	if !found[alphaPatchedPaperPath] {
		return nil, 0, fmt.Errorf("build prepared Paper runtime: %s is missing", alphaPatchedPaperPath)
	}
	if libraryFiles == 0 {
		return nil, 0, errors.New("build prepared Paper runtime: libraries contains no regular files")
	}
	if expanded == 0 {
		return nil, 0, errors.New("build prepared Paper runtime: archive would contain no file data")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	return entries, expanded, nil
}

func writePreparedRuntime(ctx context.Context, archive *tar.Writer, entries []preparedRuntimeEntry) error {
	epoch := time.Unix(0, 0).UTC()
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		header := &tar.Header{
			Name:       entry.path,
			Mode:       0o644,
			Size:       entry.size,
			Typeflag:   tar.TypeReg,
			ModTime:    epoch,
			AccessTime: time.Time{},
			ChangeTime: time.Time{},
			Format:     tar.FormatUSTAR,
		}
		if entry.isDir {
			header.Mode = 0o755
			header.Typeflag = tar.TypeDir
		}
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		if entry.isDir {
			continue
		}
		file, err := os.Open(entry.source)
		if err != nil {
			return err
		}
		copied, copyErr := io.CopyN(archive, &contextReader{ctx: ctx, reader: file}, entry.size)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		if copied != entry.size {
			return fmt.Errorf("source file %q changed while it was archived", entry.path)
		}
	}
	return nil
}

type countingWriter struct {
	writer  io.Writer
	written int64
}

func (w *countingWriter) Write(content []byte) (int, error) {
	written, err := w.writer.Write(content)
	w.written += int64(written)
	return written, err
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(content []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(content)
}
