package runtimeidentity

import (
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

// NetworkObservation is a historical, execution-bound kernel observation.
// Its fields cannot be populated by decoding JSON or supplying runtime labels.
// It grants no continuing authority and does not establish job success.
type NetworkObservation struct {
	snapshot Snapshot
	lease    *p.LeaseIdentity
	attempt  *p.AttemptIdentity
	hashes   *p.JobHashes
	observed bool
}

// SnapshotFor returns a value only for the original immutable evidence binding.
// The returned network snapshot intentionally remains invalid for the legacy
// unsealed Snapshot path. Callers must use the sealed evidence entry point.
func (o *NetworkObservation) SnapshotFor(lease *p.LeaseIdentity, attempt *p.AttemptIdentity, hashes *p.JobHashes) (Snapshot, error) {
	if o == nil || !o.observed || o.lease == nil || o.attempt == nil || o.hashes == nil || !proto.Equal(o.lease, lease) || !proto.Equal(o.attempt, attempt) || !proto.Equal(o.hashes, hashes) {
		return Snapshot{}, ErrUnavailable
	}
	return o.snapshot, nil
}
