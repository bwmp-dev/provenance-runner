package artifact

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

func TestEntryDescriptorIsVerifiedReadOnlyAndIndependentlyOwned(t *testing.T) {
	ctx := context.Background()
	cache := newTestCache(t, CacheOptions{})
	entry, err := cache.AcquireExact(ctx, SHA256([]byte("fixture")), 7, SourceFunc(func(_ context.Context, w io.Writer) error {
		_, err := io.WriteString(w, "fixture")
		return err
	}))
	if err != nil {
		t.Fatal(err)
	}
	a, err := entry.OpenDescriptor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := entry.OpenDescriptor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("writable descriptor")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(b)
	if err != nil || string(raw) != "fixture" {
		t.Fatal("descriptor ownership or initial offset", err)
	}
	if err := os.Chmod(entry.path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry.path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := entry.OpenDescriptor(ctx); f != nil || !errors.Is(err, ErrCacheCorrupt) {
		t.Fatal("same-size corruption accepted")
	}
	if err := os.WriteFile(entry.path, []byte("fixture extra"), 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := entry.OpenDescriptor(ctx); f != nil || !errors.Is(err, ErrCacheCorrupt) {
		t.Fatal("oversized cache entry accepted")
	}
}

func TestEntryDescriptorRejectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	entry := &Entry{path: t.TempDir(), size: 0}
	if f, err := entry.OpenDescriptor(ctx); f != nil || err == nil {
		t.Fatal("cancelled or non-regular descriptor accepted")
	}
	if f, err := entry.OpenDescriptor(nil); f != nil || err == nil {
		t.Fatal("missing context accepted")
	}
	if f, err := (*Entry)(nil).OpenDescriptor(context.Background()); f != nil || err == nil {
		t.Fatal("missing entry accepted")
	}
}
