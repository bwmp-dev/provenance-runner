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
