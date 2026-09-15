//go:build linux

package runtimeidentity

import "testing"

func TestPaperGuestTargetRequiresRetainedImage(t *testing.T) {
	var missing *Lease
	if missing.ValidatePaperGuestTarget() == nil || (&Lease{}).ValidatePaperGuestTarget() == nil {
		t.Fatal("unmeasured helper accepted")
	}
}
