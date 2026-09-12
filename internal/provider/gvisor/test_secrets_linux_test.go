//go:build linux

package gvisor

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	"golang.org/x/sys/unix"
)

func TestSecretMountsArePrivateReadOnlyAndBudgeted(t *testing.T) {
	f, err := testsecrets.New([]testsecrets.Input{{Name: "token", Value: []byte("synthetic")}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	spec := ociSpec{Mounts: []ociMount{{Destination: "/tmp", Type: "tmpfs", Options: []string{"size=4194304"}}}}
	p := &Provider{config: Config{StateRoot: t.TempDir()}}
	t.Cleanup(func() {
		if err := p.removeSecretTmpfs(teardownTestContainerID); err != nil {
			t.Error(err)
		}
		if err := os.Remove(p.secretTmpfsRoot()); err != nil && !os.IsNotExist(err) {
			t.Error(err)
		}
	})
	if err := p.addSecretMounts(&spec, f, teardownTestContainerID); err != nil {
		t.Fatal(err)
	}
	if len(spec.Mounts) != 2 || spec.Mounts[0].Options[0] != "size=3145728" || spec.Mounts[1].Destination != "/run" || spec.Mounts[1].Type != "bind" {
		t.Fatal("secret filesystem was not privately budgeted")
	}
	placeholder := filepath.Join(spec.Mounts[1].Source, "provenance", "test-secrets", "token")
	if data, err := os.ReadFile(placeholder); err != nil || string(data) != "synthetic" {
		t.Fatal("private tmpfs value unavailable")
	}
	if !slices.Contains(spec.Mounts[1].Options, "ro") {
		t.Fatal("metadata skeleton is guest writable")
	}
	m := spec.Mounts[1]
	if err := validateSecretTmpfsRoot(p.secretTmpfsRoot()); err != nil {
		t.Fatal("secret file source escaped private tmpfs")
	}
	for _, option := range []string{"bind", "ro", "nosuid", "nodev", "noexec"} {
		if !slices.Contains(m.Options, option) {
			t.Fatal("missing restrictive mount option")
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.addSecretMounts(&spec, f, teardownTestContainerID); err == nil {
		t.Fatal("closed memory handle accepted")
	}
}

func TestSecretTmpfsRefusesPersistentOrSymlinkStorage(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil {
		t.Fatal(err)
	}
	if err := validateSecretTmpfsRoot(root); err == nil && fs.Type != unix.TMPFS_MAGIC {
		t.Fatal("ordinary test filesystem accepted as tmpfs")
	}
	p := &Provider{config: Config{StateRoot: t.TempDir()}}
	if err := os.Symlink(root, p.secretTmpfsRoot()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(p.secretTmpfsRoot()) })
	if _, err := p.createSecretTmpfs(teardownTestContainerID); err == nil {
		t.Fatal("symlink private root accepted")
	}
	if err := p.removeSecretTmpfs(teardownTestContainerID); err == nil {
		t.Fatal("cleanup traversed symlink private root")
	}
}
