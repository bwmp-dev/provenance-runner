package artifact

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const DefaultMaximumEntryBytes int64 = 1 << 30
const DefaultMaximumTotalBytes int64 = 16 << 30

var (
	ErrCacheCorrupt       = errors.New("artifact cache entry is corrupt")
	ErrDigestMismatch     = errors.New("artifact SHA-256 does not match expected digest")
	ErrEntryTooLarge      = errors.New("artifact exceeds cache entry size limit")
	ErrSizeMismatch       = errors.New("artifact size does not match declared size")
	ErrCacheQuotaExceeded = errors.New("artifact cache total-byte quota exceeded")
)

type CacheOptions struct {
	MaximumEntryBytes int64
	MaximumTotalBytes int64
}

type Cache struct {
	root              string
	maximumEntryBytes int64
	maximumTotalBytes int64
	quotaMu           sync.Mutex
	lockMu            sync.Mutex
	locks             map[string]*keyLock
}

type keyLock struct {
	token chan struct{}
	users int
}

func NewCache(root string, options CacheOptions) (*Cache, error) {
	if root == "" {
		return nil, errors.New("create artifact cache: root is empty")
	}
	if options.MaximumEntryBytes < 0 {
		return nil, errors.New("create artifact cache: maximum entry size cannot be negative")
	}
	if options.MaximumTotalBytes < 0 {
		return nil, errors.New("create artifact cache: maximum total size cannot be negative")
	}
	if options.MaximumEntryBytes == 0 {
		options.MaximumEntryBytes = DefaultMaximumEntryBytes
	}
	if options.MaximumTotalBytes == 0 {
		options.MaximumTotalBytes = DefaultMaximumTotalBytes
	}
	if options.MaximumEntryBytes > options.MaximumTotalBytes {
		return nil, errors.New("create artifact cache: entry size limit exceeds total size limit")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("create artifact cache: resolve root: %w", err)
	}
	if err := os.MkdirAll(absoluteRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create artifact cache root: %w", err)
	}
	if err := os.Chmod(absoluteRoot, 0o700); err != nil {
		return nil, fmt.Errorf("restrict artifact cache root: %w", err)
	}
	info, err := os.Stat(absoluteRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect artifact cache root: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("create artifact cache: root is not a directory")
	}
	return &Cache{
		root:              absoluteRoot,
		maximumEntryBytes: options.MaximumEntryBytes,
		maximumTotalBytes: options.MaximumTotalBytes,
		locks:             make(map[string]*keyLock),
	}, nil
}

func (c *Cache) Acquire(ctx context.Context, expected Digest, source Source) (*Entry, error) {
	return c.acquire(ctx, expected, c.maximumEntryBytes, false, source)
}

func (c *Cache) AcquireExact(ctx context.Context, expected Digest, expectedBytes int64, source Source) (*Entry, error) {
	if expectedBytes <= 0 || expectedBytes > c.maximumEntryBytes {
		return nil, fmt.Errorf("acquire artifact: declared size must be between 1 and %d", c.maximumEntryBytes)
	}
	return c.acquire(ctx, expected, expectedBytes, true, source)
}

func (c *Cache) acquire(ctx context.Context, expected Digest, maximumBytes int64, exact bool, source Source) (*Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("acquire artifact: %w", err)
	}
	unlock, err := c.lock(ctx, expected.CacheKey())
	if err != nil {
		return nil, fmt.Errorf("acquire artifact: %w", err)
	}
	defer unlock()
	c.quotaMu.Lock()
	defer c.quotaMu.Unlock()

	entry, exists, err := c.existingEntry(ctx, expected)
	if err != nil {
		return nil, err
	}
	if exists {
		if exact && entry.Size() != maximumBytes {
			return nil, fmt.Errorf("%w: expected %d bytes, cached %d", ErrSizeMismatch, maximumBytes, entry.Size())
		}
		return entry, nil
	}
	if source == nil {
		return nil, errors.New("acquire artifact: source is required on a cache miss")
	}
	currentBytes, err := c.currentBytes(ctx)
	if err != nil {
		return nil, err
	}
	if maximumBytes > c.maximumTotalBytes-currentBytes {
		return nil, fmt.Errorf("%w: current %d, requested %d, limit %d", ErrCacheQuotaExceeded, currentBytes, maximumBytes, c.maximumTotalBytes)
	}

	targetPath := c.entryPath(expected)
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return nil, fmt.Errorf("create artifact cache directory: %w", err)
	}
	temporaryFile, err := os.CreateTemp(filepath.Dir(targetPath), ".artifact-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary cache entry: %w", err)
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)

	writer := &verifyingWriter{
		ctx:     ctx,
		file:    temporaryFile,
		hash:    sha256.New(),
		maximum: maximumBytes,
	}
	fetchErr := source.Fetch(ctx, writer)
	if fetchErr == nil {
		fetchErr = writer.err
	}
	if fetchErr == nil {
		fetchErr = ctx.Err()
	}
	if fetchErr != nil {
		temporaryFile.Close()
		return nil, fmt.Errorf("acquire artifact: %w", fetchErr)
	}
	if exact && writer.written != maximumBytes {
		temporaryFile.Close()
		return nil, fmt.Errorf("%w: expected %d bytes, received %d", ErrSizeMismatch, maximumBytes, writer.written)
	}

	var actual Digest
	copy(actual[:], writer.hash.Sum(nil))
	if actual != expected {
		temporaryFile.Close()
		return nil, fmt.Errorf("%w: expected %s, received %s", ErrDigestMismatch, expected, actual)
	}
	if err := temporaryFile.Sync(); err != nil {
		temporaryFile.Close()
		return nil, fmt.Errorf("sync temporary cache entry: %w", err)
	}
	if err := temporaryFile.Close(); err != nil {
		return nil, fmt.Errorf("close temporary cache entry: %w", err)
	}
	if err := os.Chmod(temporaryPath, 0o444); err != nil {
		return nil, fmt.Errorf("make cache entry read-only: %w", err)
	}

	if err := os.Link(temporaryPath, targetPath); err != nil {
		if !os.IsExist(err) {
			return nil, fmt.Errorf("publish cache entry atomically: %w", err)
		}
		entry, exists, existingErr := c.existingEntry(ctx, expected)
		if existingErr != nil {
			return nil, existingErr
		}
		if !exists {
			return nil, errors.New("publish cache entry atomically: target disappeared")
		}
		if exact && entry.Size() != maximumBytes {
			return nil, fmt.Errorf("%w: expected %d bytes, cached %d", ErrSizeMismatch, maximumBytes, entry.Size())
		}
		return entry, nil
	}

	return &Entry{
		digest: expected,
		path:   targetPath,
		size:   writer.written,
	}, nil
}

func (c *Cache) currentBytes(ctx context.Context) (int64, error) {
	var total int64
	err := filepath.WalkDir(c.root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("inspect artifact cache quota: symbolic link %q is not permitted", path)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > c.maximumTotalBytes-total {
			return errors.New("inspect artifact cache quota: invalid or oversized cache content")
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("inspect artifact cache quota: %w", err)
	}
	return total, nil
}

func (c *Cache) existingEntry(ctx context.Context, expected Digest) (*Entry, bool, error) {
	path := c.entryPath(expected)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect cache entry: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%w: %s is not a regular file", ErrCacheCorrupt, expected.CacheKey())
	}
	if info.Size() > c.maximumEntryBytes {
		return nil, false, fmt.Errorf("%w: %s is larger than the configured limit", ErrCacheCorrupt, expected.CacheKey())
	}
	entry := &Entry{digest: expected, path: path, size: info.Size()}
	reader, err := entry.Open(ctx)
	if err != nil {
		return nil, false, err
	}
	if err := reader.Close(); err != nil {
		return nil, false, fmt.Errorf("close verified cache entry: %w", err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		return nil, false, fmt.Errorf("make existing cache entry read-only: %w", err)
	}
	return entry, true, nil
}

func (c *Cache) entryPath(digest Digest) string {
	encoded := digest.String()
	return filepath.Join(c.root, "sha256", encoded[:2], encoded[2:])
}

func (c *Cache) lock(ctx context.Context, key string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.lockMu.Lock()
	lock := c.locks[key]
	if lock == nil {
		lock = &keyLock{token: make(chan struct{}, 1)}
		lock.token <- struct{}{}
		c.locks[key] = lock
	}
	lock.users++
	c.lockMu.Unlock()

	select {
	case <-ctx.Done():
		c.releaseLockReference(key, lock)
		return nil, ctx.Err()
	case <-lock.token:
		unlock := func() {
			lock.token <- struct{}{}
			c.releaseLockReference(key, lock)
		}
		if err := ctx.Err(); err != nil {
			unlock()
			return nil, err
		}
		return unlock, nil
	}
}

func (c *Cache) releaseLockReference(key string, lock *keyLock) {
	c.lockMu.Lock()
	defer c.lockMu.Unlock()
	lock.users--
	if lock.users == 0 {
		delete(c.locks, key)
	}
}

type Entry struct {
	digest Digest
	path   string
	size   int64
}

func (e *Entry) Digest() Digest {
	return e.digest
}

func (e *Entry) CacheKey() string {
	return e.digest.CacheKey()
}

func (e *Entry) Size() int64 {
	return e.size
}

// Open verifies the entry before returning a read-only stream. Callers must not use
// data copied from the stream if a later read returns an error.
func (e *Entry) Open(ctx context.Context) (io.ReadCloser, error) {
	if e == nil {
		return nil, errors.New("open cache entry: entry is nil")
	}
	file, err := os.Open(e.path)
	if err != nil {
		return nil, fmt.Errorf("open cache entry: %w", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, &contextReader{ctx: ctx, reader: file}); err != nil {
		file.Close()
		return nil, fmt.Errorf("verify cache entry: %w", err)
	}
	var actual Digest
	copy(actual[:], hasher.Sum(nil))
	if actual != e.digest {
		file.Close()
		return nil, fmt.Errorf("%w: expected %s, received %s", ErrCacheCorrupt, e.digest, actual)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, fmt.Errorf("rewind cache entry: %w", err)
	}
	return &readOnlyEntry{file: file}, nil
}

type readOnlyEntry struct {
	file *os.File
}

func (r *readOnlyEntry) Read(buffer []byte) (int, error) {
	return r.file.Read(buffer)
}

func (r *readOnlyEntry) Close() error {
	return r.file.Close()
}

type verifyingWriter struct {
	ctx     context.Context
	file    *os.File
	hash    hash.Hash
	maximum int64
	written int64
	err     error
}

func (w *verifyingWriter) Write(buffer []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if err := w.ctx.Err(); err != nil {
		w.err = err
		return 0, err
	}
	if int64(len(buffer)) > w.maximum-w.written {
		w.err = ErrEntryTooLarge
		return 0, w.err
	}
	written, err := w.file.Write(buffer)
	if written > 0 {
		_, _ = w.hash.Write(buffer[:written])
		w.written += int64(written)
	}
	if err != nil {
		w.err = err
		return written, err
	}
	if written != len(buffer) {
		w.err = io.ErrShortWrite
		return written, w.err
	}
	return written, nil
}
