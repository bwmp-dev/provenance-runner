package runtimeidentity

import (
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestNetworkObservationBindingCannotBeReassigned(t *testing.T) {
	lease := &p.LeaseIdentity{JobId: "job", LeaseId: "lease", ExecutionId: "execution"}
	attempt := &p.AttemptIdentity{AttemptId: "attempt", ReleaseCandidateId: "candidate", MatrixEntryId: "matrix", AttemptNumber: 1}
	hashes := &p.JobHashes{Policy: &p.Digest{Value: []byte{1}}, Artifact: &p.Digest{Value: []byte{2}}}
	// Only this package's test can construct private historical state. The
	// Linux constructor is exercised separately with real retained objects.
	o := &NetworkObservation{lease: lease, attempt: attempt, hashes: hashes, observed: true, snapshot: Snapshot{NetworkMode: "allowlist"}}
	got, err := o.SnapshotFor(lease, attempt, hashes)
	if err != nil || got.NetworkMode != "allowlist" || got.Valid() {
		t.Fatal("sealed historical projection")
	}
	got.NetworkMode = "restricted"
	for _, mutate := range []func(*p.LeaseIdentity, *p.AttemptIdentity, *p.JobHashes){
		func(l *p.LeaseIdentity, a *p.AttemptIdentity, h *p.JobHashes) { l.JobId = "other" },
		func(l *p.LeaseIdentity, a *p.AttemptIdentity, h *p.JobHashes) { l.LeaseId = "other" },
		func(l *p.LeaseIdentity, a *p.AttemptIdentity, h *p.JobHashes) { l.ExecutionId = "other" },
		func(l *p.LeaseIdentity, a *p.AttemptIdentity, h *p.JobHashes) { a.AttemptId = "other" },
		func(l *p.LeaseIdentity, a *p.AttemptIdentity, h *p.JobHashes) { a.ReleaseCandidateId = "other" },
		func(l *p.LeaseIdentity, a *p.AttemptIdentity, h *p.JobHashes) { a.MatrixEntryId = "other" },
		func(l *p.LeaseIdentity, a *p.AttemptIdentity, h *p.JobHashes) { a.AttemptNumber++ },
		func(l *p.LeaseIdentity, a *p.AttemptIdentity, h *p.JobHashes) { h.Policy.Value[0]++ },
		func(l *p.LeaseIdentity, a *p.AttemptIdentity, h *p.JobHashes) { h.Artifact.Value[0]++ },
	} {
		l, a, h := proto.Clone(lease).(*p.LeaseIdentity), proto.Clone(attempt).(*p.AttemptIdentity), proto.Clone(hashes).(*p.JobHashes)
		mutate(l, a, h)
		if _, err := o.SnapshotFor(l, a, h); err == nil {
			t.Fatal("foreign binding accepted")
		}
	}
	if current, err := o.SnapshotFor(lease, attempt, hashes); err != nil || current.NetworkMode != "allowlist" {
		t.Fatal("returned value mutated observation")
	}
}
