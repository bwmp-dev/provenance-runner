//go:build linux

package runtimeidentity

import (
	"context"
	"testing"
)

func TestNetworkObservationCannotBeCreatedWithoutRetainedOwners(t *testing.T) {
	for _, lease := range []*Lease{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if observed, err := lease.ObserveNetwork(ctx, nil, nil, "", nil, nil); err == nil || observed != nil {
				t.Fatal("missing owners minted observation")
			}
		}
	}
}
