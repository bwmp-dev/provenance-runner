//go:build linux

package runtimeidentity

import "testing"

func TestSecretTargetRequiresRetainedMeasuredImage(t *testing.T) {
	for _, l := range []*Lease{nil, {}} {
		if l.ValidateTestSecretTarget() == nil {
			t.Fatal("unmeasured mountpoint accepted")
		}
	}
}
