//go:build linux

package runtimeidentity

import (
	"bytes"
	"encoding/json"

	"github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func networkObservationJobHash(job *p.JobSpecification) ([32]byte, error) {
	if job == nil || proto.Size(job) > 1<<20 {
		return [32]byte{}, ErrUnavailable
	}
	if _, err := np.NewAuthority(job); err != nil {
		return [32]byte{}, ErrUnavailable
	}
	return ExecutionJobSHA256(job)
}

func validProxySnapshot(job *p.JobSpecification, snapshot Snapshot) bool {
	mode := map[p.NetworkMode]string{p.NetworkMode_NETWORK_MODE_ALLOWLIST: "allowlist", p.NetworkMode_NETWORK_MODE_RESTRICTED: "restricted"}[job.GetEffectivePolicy().GetNetworkV2().GetMode()]
	if mode == "" || snapshot.NetworkMode != mode {
		return false
	}
	snapshot.NetworkMode = "none"
	return snapshot.Valid()
}

// EncodeRootObservation exports only an already sealed kernel observation of
// this full job. The root service sends it under the dedicated Observation kind,
// never by copying a message kind or payload supplied by the guest.
func EncodeRootObservation(job *p.JobSpecification, observed *NetworkObservation) ([]byte, error) {
	hash, err := networkObservationJobHash(job)
	if err != nil || observed == nil || observed.jobSHA256 != hash {
		return nil, ErrUnavailable
	}
	snapshot, err := observed.SnapshotFor(job.Lease, job.Attempt, job.Hashes)
	if err != nil || !validProxySnapshot(job, snapshot) {
		return nil, ErrUnavailable
	}
	raw, err := json.Marshal(snapshot)
	if err != nil || len(raw) > 4096 {
		return nil, ErrUnavailable
	}
	encoded := make([]byte, 36+len(raw))
	copy(encoded, "PVO1")
	copy(encoded[4:36], hash[:])
	copy(encoded[36:], raw)
	return encoded, nil
}

// ImportRootObservation accepts the dedicated packet received directly from an
// authenticated root controller. Raw bytes, a plain Snapshot or a JSON-decoded
// receipt cannot enter this path. It delegates historical observation to that
// privileged owner, not to guest claims, and grants no continuing route authority.
func ImportRootObservation(job *p.JobSpecification, packet *controlchannel.RootObservationPacket) (*NetworkObservation, error) {
	hash, err := networkObservationJobHash(job)
	if err != nil {
		return nil, ErrUnavailable
	}
	raw, authenticated := packet.Payload()
	if !authenticated || len(raw) <= 36 || len(raw) > 36+4096 || string(raw[:4]) != "PVO1" || !bytes.Equal(raw[4:36], hash[:]) {
		return nil, ErrUnavailable
	}
	var snapshot Snapshot
	if json.Unmarshal(raw[36:], &snapshot) != nil || !validProxySnapshot(job, snapshot) {
		return nil, ErrUnavailable
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil || !bytes.Equal(raw[36:], canonical) {
		return nil, ErrUnavailable
	}
	return &NetworkObservation{snapshot: snapshot, lease: proto.Clone(job.Lease).(*p.LeaseIdentity), attempt: proto.Clone(job.Attempt).(*p.AttemptIdentity), hashes: proto.Clone(job.Hashes).(*p.JobHashes), observed: true, jobSHA256: hash}, nil
}
