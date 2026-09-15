//go:build linux

package runtimeidentity

import "testing"

func TestChildObjectMeasurementRejectsMissingOwners(t *testing.T) {
	for _, lease := range []*Lease{nil, {}} {
		if lease.ValidateChildObjects(nil, "", "") != ErrUnavailable {
			t.Fatal("missing retained objects produced a measurement")
		}
	}
}
