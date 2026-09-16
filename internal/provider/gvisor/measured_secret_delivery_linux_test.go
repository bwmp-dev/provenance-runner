//go:build linux

package gvisor

import (
	"context"
	"testing"
	"time"
)

func TestMeasuredSecretDeliveryRequiresObservedOwner(t *testing.T) {
	for _, c := range []*measuredController{nil, {}} {
		if c.SupportsTestSecretStorage() {
			t.Fatal("unprovisioned storage advertised")
		}
	}
	for _, j := range []*measuredControllerJob{nil, {}, {controller: &measuredController{}}} {
		if j.MaterializeTestSecrets(context.Background(), nil, time.Now().Add(time.Minute)) == nil {
			t.Fatal("unobserved owner accepted")
		}
	}
}
