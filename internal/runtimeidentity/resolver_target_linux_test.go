//go:build linux

package runtimeidentity

import "testing"

func TestResolverTargetRequiresRetainedImage(t *testing.T) {
	for _, lease := range []*Lease{nil, {}, {closed: true}} {
		if lease.ValidateResolverTarget() == nil {
			t.Fatal("unmeasured resolver target accepted")
		}
	}
}
