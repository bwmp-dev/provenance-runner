package artifact

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheAcquireAndVerifiedRead(t *testing.T) {
	payload := []byte("fixture artifact")
	digest := SHA256(payload)
	cache := newTestCache(t, CacheOptions{})
	rootInfo, err := os.Stat(cache.root)
	if err != nil {
		t.Fatalf("cache root Stat() error = %v", err)
	}
	if runtime.GOOS != "windows" && rootInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("cache root mode = %v, want private", rootInfo.Mode().Perm())
	}
	var fetches atomic.Int32
	source := SourceFunc(func(_ context.Context, destination io.Writer) error {
		fetches.Add(1)
		_, err := destination.Write(payload)
		return err
	})

	entry, err := cache.Acquire(context.Background(), digest, source)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if entry.CacheKey() != "sha256:"+digest.String() {
		t.Fatalf("CacheKey() = %q", entry.CacheKey())
	}
	if entry.Size() != int64(len(payload)) {
		t.Fatalf("Size() = %d, want %d", entry.Size(), len(payload))
	}
	if _, err := cache.Acquire(context.Background(), digest, nil); err != nil {
		t.Fatalf("Acquire() cached error = %v", err)
	}
	if fetches.Load() != 1 {
		t.Fatalf("fetch count = %d, want 1", fetches.Load())
	}

	reader, err := entry.Open(context.Background())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if string(content) != string(payload) {
		t.Fatalf("content = %q, want %q", content, payload)
	}
	info, err := os.Stat(cache.entryPath(digest))
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("cache entry mode = %v, want read-only", info.Mode().Perm())
	}
}

func TestCacheRejectsDigestMismatchWithoutPublishing(t *testing.T) {
	payload := []byte("expected")
	digest := SHA256(payload)
	cache := newTestCache(t, CacheOptions{})

	_, err := cache.Acquire(context.Background(), digest, SourceFunc(func(_ context.Context, destination io.Writer) error {
		_, writeErr := destination.Write([]byte("different"))
		return writeErr
	}))
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("Acquire() error = %v, want ErrDigestMismatch", err)
	}
	if _, err := os.Stat(cache.entryPath(digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache entry Stat() error = %v, want not exist", err)
	}
	if _, err := cache.Acquire(context.Background(), digest, bytesSource(payload)); err != nil {
		t.Fatalf("Acquire() after mismatch error = %v", err)
	}
}

func TestCacheEnforcesMaximumEntrySize(t *testing.T) {
	cache := newTestCache(t, CacheOptions{MaximumEntryBytes: 4})
	payload := []byte("12345")
	_, err := cache.Acquire(context.Background(), SHA256(payload), bytesSource(payload))
	if !errors.Is(err, ErrEntryTooLarge) {
		t.Fatalf("Acquire() error = %v, want ErrEntryTooLarge", err)
	}
}

func TestCacheSerializesConcurrentAcquisition(t *testing.T) {
	payload := []byte("concurrent fixture")
	digest := SHA256(payload)
	cache := newTestCache(t, CacheOptions{})
	var fetches atomic.Int32
	fetchStarted := make(chan struct{})
	releaseFetch := make(chan struct{})
	source := SourceFunc(func(_ context.Context, destination io.Writer) error {
		if fetches.Add(1) == 1 {
			close(fetchStarted)
		}
		<-releaseFetch
		_, err := destination.Write(payload)
		return err
	})

	const workers = 24
	results := make(chan error, workers)
	for range workers {
		go func() {
			_, err := cache.Acquire(context.Background(), digest, source)
			results <- err
		}()
	}
	<-fetchStarted
	close(releaseFetch)
	for range workers {
		if err := <-results; err != nil {
			t.Fatalf("concurrent Acquire() error = %v", err)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("fetch count = %d, want 1", fetches.Load())
	}
}

func TestCachePublishesSafelyAcrossInstances(t *testing.T) {
	payload := []byte("cross-instance fixture")
	digest := SHA256(payload)
	root := t.TempDir()
	first, err := NewCache(root, CacheOptions{})
	if err != nil {
		t.Fatalf("NewCache(first) error = %v", err)
	}
	second, err := NewCache(root, CacheOptions{})
	if err != nil {
		t.Fatalf("NewCache(second) error = %v", err)
	}
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	source := SourceFunc(func(_ context.Context, destination io.Writer) error {
		if _, err := destination.Write(payload); err != nil {
			return err
		}
		arrived <- struct{}{}
		<-release
		return nil
	})

	results := make(chan error, 2)
	for _, cache := range []*Cache{first, second} {
		go func(cache *Cache) {
			_, err := cache.Acquire(context.Background(), digest, source)
			results <- err
		}(cache)
	}
	<-arrived
	<-arrived
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("Acquire() error = %v", err)
		}
	}
	entry, err := first.Acquire(context.Background(), digest, nil)
	if err != nil {
		t.Fatalf("Acquire() published entry error = %v", err)
	}
	reader, err := entry.Open(context.Background())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	content, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || string(content) != string(payload) {
		t.Fatalf("published content = %q, error = %v", content, err)
	}
}

func TestCacheLockWaitHonorsCancellation(t *testing.T) {
	payload := []byte("fixture")
	digest := SHA256(payload)
	cache := newTestCache(t, CacheOptions{})
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := cache.Acquire(context.Background(), digest, SourceFunc(func(_ context.Context, destination io.Writer) error {
			close(started)
			<-release
			_, writeErr := destination.Write(payload)
			return writeErr
		}))
		firstDone <- err
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := cache.Acquire(ctx, digest, bytesSource(payload))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting Acquire() error = %v, want deadline exceeded", err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Acquire() error = %v", err)
	}
}

func TestEntryOpenDetectsCacheCorruption(t *testing.T) {
	payload := []byte("fixture")
	digest := SHA256(payload)
	cache := newTestCache(t, CacheOptions{})
	entry, err := cache.Acquire(context.Background(), digest, bytesSource(payload))
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	path := cache.entryPath(digest)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := entry.Open(context.Background()); !errors.Is(err, ErrCacheCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCacheCorrupt", err)
	}
	if _, err := cache.Acquire(context.Background(), digest, bytesSource(payload)); !errors.Is(err, ErrCacheCorrupt) {
		t.Fatalf("Acquire() corrupted entry error = %v, want ErrCacheCorrupt", err)
	}
}

func newTestCache(t *testing.T, options CacheOptions) *Cache {
	t.Helper()
	cache, err := NewCache(t.TempDir(), options)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	return cache
}

func bytesSource(content []byte) Source {
	return SourceFunc(func(_ context.Context, destination io.Writer) error {
		_, err := destination.Write(content)
		return err
	})
}

func TestDigestRoundTrip(t *testing.T) {
	digest := SHA256([]byte("fixture"))
	parsed, err := ParseSHA256(digest.String())
	if err != nil {
		t.Fatalf("ParseSHA256() error = %v", err)
	}
	if parsed != digest {
		t.Fatalf("ParseSHA256() = %s, want %s", parsed, digest)
	}
	if _, err := ParseSHA256("not-a-digest"); err == nil {
		t.Fatal("ParseSHA256() error = nil")
	}
}
