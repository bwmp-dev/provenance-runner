//go:build linux

package networkpolicy

import (
	"context"
	"testing"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func TestChildObservationRefusesMissingOrSimulatedOwnership(t *testing.T) {
	var absent *AuthorityRoute
	if absent.ObserveInstalledForChild(context.Background(), nil, nil) == nil {
		t.Fatal("missing authority accepted")
	}
	for _, child := range []*ChildNamespaces{nil, {}} {
		s, r, f, c, b, route := authorityRouteFixture(t)
		startAuthorityRoute(t, s, r, f, c, b, route)
		_, job, _, _, _, _ := authorityFixture(t)
		job.Lease = proto.Clone(r.Lease).(*p.LeaseIdentity)
		if s.ObserveInstalledForChild(context.Background(), job, child) == nil {
			t.Fatal("simulated actuator or child accepted")
		}
		select {
		case <-s.Done():
		default:
			t.Fatal("failed child observation did not withdraw")
		}
		if s.CheckJob(job) == nil {
			t.Fatal("failed observation revived")
		}
	}
}
