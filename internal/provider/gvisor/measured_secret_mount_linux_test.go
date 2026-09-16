//go:build linux

package gvisor

import (
	"context"
	"testing"
	"time"
)

func TestMeasuredSecretMountRequiresOwnedPreparation(t *testing.T) {
	for _, b := range []*measuredBundle{nil, {}, {owner: &measuredBundleJournal{}}} {
		if b.stageSecrets(context.Background(), nil, nil, time.Now().Add(time.Minute)) == nil {
			t.Fatal("unowned materialization accepted")
		}
	}
	for _, path := range []string{"", "/", "relative", "/tmp/../tmp", "/missing-measured-secret-root"} {
		j := &measuredBundleJournal{secretPath: path}
		if j.secretPathValid() {
			t.Fatal("unretained secret pathname accepted")
		}
	}
}

func TestMeasuredSecretMountReservesExistingDiskBudget(t *testing.T) {
	for _, spec := range []*ociSpec{nil, {}, {Mounts: []ociMount{{Destination: "/tmp", Type: "tmpfs", Options: []string{"size=1048576"}}}}} {
		if reserveMeasuredSecretStorage(spec) == nil {
			t.Fatal("missing reserve accepted")
		}
	}
	spec := &ociSpec{Mounts: []ociMount{{Destination: "/tmp", Type: "tmpfs", Options: []string{"size=4194304", "nosuid"}}}}
	if reserveMeasuredSecretStorage(spec) != nil || spec.Mounts[0].Options[0] != "size=3145728" || spec.Mounts[0].Options[1] != "nosuid" {
		t.Fatal("secret disk reserve")
	}
}
