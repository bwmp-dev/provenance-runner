package workspace

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestArchiveLinkRefusesEarlierSymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links require optional Windows privileges")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "safe"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := materializeArchiveLink(root, pendingLink{path: filepath.Join(root, "a", "b"), target: "../safe", typeflag: tar.TypeSymlink}); err != nil {
		t.Fatal(err)
	}
	// The lexical parent has depth two, but the earlier link resolves to depth
	// one. No archive object may be created through that substituted parent.
	if err := materializeArchiveLink(root, pendingLink{path: filepath.Join(root, "a", "b", "child"), target: "../../outside", typeflag: tar.TypeSymlink}); err == nil {
		t.Fatal("archive link traversed an earlier symlink parent")
	}
	if _, err := os.Lstat(filepath.Join(root, "safe", "child")); !os.IsNotExist(err) {
		t.Fatal("refused link left an object behind")
	}
}

func TestArchiveHardlinkRequiresRegularRealTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links require optional Windows privileges")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("synthetic"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := materializeArchiveLink(root, pendingLink{path: filepath.Join(root, "alias"), target: "file", typeflag: tar.TypeSymlink}); err != nil {
		t.Fatal(err)
	}
	if err := materializeArchiveLink(root, pendingLink{path: filepath.Join(root, "bad"), target: "alias", typeflag: tar.TypeLink}); err == nil {
		t.Fatal("hardlink adopted a symbolic link")
	}
	if err := materializeArchiveLink(root, pendingLink{path: filepath.Join(root, "good"), target: "file", typeflag: tar.TypeLink}); err != nil {
		t.Fatal("regular hardlink refused", err)
	}
}

func TestArchiveRefusedLinkTreeIsNeverPublished(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links require optional Windows privileges")
	}
	entry := cachedEntry(t, tarGzip(t, []tarEntry{
		{name: "safe/", typeflag: tar.TypeDir},
		{name: "a/b", typeflag: tar.TypeSymlink, linkname: "../safe"},
		{name: "a/b/child", typeflag: tar.TypeSymlink, linkname: "../../outside"},
	}))
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	owned, err := manager.Create(context.Background(), "archive-boundary")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.Cleanup(context.Background()) })
	if _, err := owned.ExtractTarGzip(context.Background(), "java", entry); err == nil {
		t.Fatal("invalid link tree published")
	}
	if _, err := os.Lstat(filepath.Join(owned.Root(), "java")); !os.IsNotExist(err) {
		t.Fatal("failed extraction published a directory")
	}
	left, err := filepath.Glob(filepath.Join(owned.Root(), ".extract-*"))
	if err != nil || len(left) != 0 {
		t.Fatal("failed extraction left a temporary tree")
	}
}
