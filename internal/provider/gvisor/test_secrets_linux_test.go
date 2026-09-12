//go:build linux

package gvisor

import (
	"slices"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
)

func TestSecretMountsArePrivateReadOnlyAndBudgeted(t *testing.T) {
	f, err := testsecrets.New([]testsecrets.Input{{Name: "token", Value: []byte("synthetic")}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	spec := ociSpec{Mounts: []ociMount{{Destination: "/tmp", Type: "tmpfs", Options: []string{"size=4194304"}}}}
	if err := addSecretMounts(&spec, f); err != nil {
		t.Fatal(err)
	}
	if len(spec.Mounts) != 3 || spec.Mounts[0].Options[0] != "size=3145728" || spec.Mounts[1].Destination != "/run" || spec.Mounts[1].Type != "tmpfs" {
		t.Fatal("secret filesystem was not privately budgeted")
	}
	m := spec.Mounts[2]
	if m.Destination != "/run/provenance/test-secrets/token" || !strings.HasPrefix(m.Source, "/proc/") {
		t.Fatal("secret file source escaped memory handles")
	}
	for _, option := range []string{"bind", "ro", "nosuid", "nodev", "noexec"} {
		if !slices.Contains(m.Options, option) {
			t.Fatal("missing restrictive mount option")
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := addSecretMounts(&spec, f); err == nil {
		t.Fatal("closed memory handle accepted")
	}
}
