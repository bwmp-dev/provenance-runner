package workspace

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveReaderPreservesLimitsAndPrivatePublication(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	owned, err := manager.Create(context.Background(), "reader")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.Cleanup(context.Background()) })
	raw := tarGzip(t, []tarEntry{{name: "runtime/bin/java", content: []byte("synthetic executable bytes"), mode: 0500}})
	root, err := owned.ExtractTarGzipReaderBounded(context.Background(), "good", bytes.NewReader(raw), 100)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "runtime/bin/java"))
	if err != nil || string(data) != "synthetic executable bytes" {
		t.Fatal("reader content changed")
	}
	if _, err := owned.ExtractTarGzipReaderBounded(context.Background(), "small", bytes.NewReader(raw), 1); err == nil {
		t.Fatal("expanded limit ignored")
	}
	if _, err := os.Lstat(filepath.Join(owned.Root(), "small")); !os.IsNotExist(err) {
		t.Fatal("failed reader published")
	}
	bad := tarGzip(t, []tarEntry{{name: "device", typeflag: tar.TypeChar}})
	if _, err := owned.ExtractTarGzipReaderBounded(context.Background(), "bad", bytes.NewReader(bad), 100); err == nil {
		t.Fatal("special entry accepted")
	}
	if _, err := owned.ExtractTarGzipReaderBounded(context.Background(), "nil", nil, 100); err == nil {
		t.Fatal("nil reader")
	}
}
