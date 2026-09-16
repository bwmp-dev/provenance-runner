package networkpolicy

import (
	"context"
	"testing"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCurrentLeaseExpiryUsesAcceptedRenewal(t *testing.T) {
	s, receipt, features, credential, _, _ := authorityRouteFixture(t)
	_, job, _, _, _, _ := authorityFixture(t)
	job.Lease = proto.Clone(receipt.Lease).(*p.LeaseIdentity)
	if err := s.Reconcile(context.Background(), receipt, features, credential); err != nil {
		t.Fatal(err)
	}
	original := job.Lease.ExpiresAt.AsTime()
	if got, err := s.CurrentLeaseExpiry(job); err != nil || !got.Equal(original) {
		t.Fatal("accepted lease missing")
	}
	renewed := proto.Clone(receipt).(*p.LeaseReconciliation)
	renewed.Lease.ExpiresAt = timestamppb.New(original.Add(time.Minute))
	renewed.NetworkAuthorityV2.CheckedAt = timestamppb.New(time.Now().Add(time.Millisecond))
	renewed.NetworkAuthorityV2.ExpiresAt = timestamppb.New(time.Now().Add(41 * time.Second))
	if err := s.Reconcile(context.Background(), renewed, features, credential); err != nil {
		t.Fatal(err)
	}
	if got, err := s.CurrentLeaseExpiry(job); err != nil || !got.Equal(renewed.Lease.ExpiresAt.AsTime()) {
		t.Fatal("original offer substituted for renewed lease")
	}
	if !job.Lease.ExpiresAt.AsTime().Equal(original) {
		t.Fatal("immutable job mutated")
	}
	wrong := proto.Clone(job).(*p.JobSpecification)
	wrong.Attempt.AttemptId = "22222222-2222-2222-2222-222222222222"
	if got, err := s.CurrentLeaseExpiry(wrong); err == nil || !got.IsZero() {
		t.Fatal("foreign attempt accepted")
	}
	if got, err := s.CurrentLeaseExpiry(job); err == nil || !got.IsZero() {
		t.Fatal("withdrawn owner resumed")
	}
}

func TestCurrentLeaseExpiryRequiresLiveAuthority(t *testing.T) {
	for _, s := range []*AuthorityRoute{nil, {}} {
		if got, err := s.CurrentLeaseExpiry(nil); err == nil || !got.IsZero() {
			t.Fatal("empty owner accepted")
		}
	}
	s, receipt, _, _, _, _ := authorityRouteFixture(t)
	_, job, _, _, _, _ := authorityFixture(t)
	job.Lease = proto.Clone(receipt.Lease).(*p.LeaseIdentity)
	if got, err := s.CurrentLeaseExpiry(job); err == nil || !got.IsZero() {
		t.Fatal("unacknowledged offer granted expiry")
	}
}
