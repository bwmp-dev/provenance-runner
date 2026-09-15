//go:build linux

package runtimeidentity

import (
	"context"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

// ObserveNetwork combines live object measurement, exact-child kernel resource
// enforcement and current native route authority. All inputs are trusted
// retained owners, never workload-supplied paths/PIDs or serialized proofs.
func (l *Lease) ObserveNetwork(ctx context.Context, job *p.JobSpecification, child *np.ChildNamespaces, privateRoot string, resources *np.RetainedResources, authority *np.AuthorityRoute, link *np.PrivateJobLink, uplink *np.HostUplink) (*NetworkObservation, error) {
	if ctx == nil || ctx.Err() != nil || job == nil || child == nil || resources == nil || authority == nil {
		return nil, ErrUnavailable
	}
	job = proto.Clone(job).(*p.JobSpecification)
	if _, err := np.NewAuthority(job); err != nil {
		return nil, ErrUnavailable
	}
	mode := map[p.NetworkMode]string{p.NetworkMode_NETWORK_MODE_RESTRICTED: "restricted", p.NetworkMode_NETWORK_MODE_ALLOWLIST: "allowlist"}[job.EffectivePolicy.NetworkV2.Mode]
	if mode == "" || resources.ValidateForChild(job, child) != nil || authority.ObserveInstalledForUplink(ctx, job, child, link, uplink) != nil || l.ValidateChildObjects(child, job.Lease.JobId, privateRoot) != nil || resources.ValidateForChild(job, child) != nil || authority.ObserveInstalledForUplink(ctx, job, child, link, uplink) != nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	snapshot := l.Snapshot()
	if !snapshot.Valid() {
		return nil, ErrUnavailable
	}
	snapshot.NetworkMode = mode
	return &NetworkObservation{snapshot: snapshot, lease: proto.Clone(job.Lease).(*p.LeaseIdentity), attempt: proto.Clone(job.Attempt).(*p.AttemptIdentity), hashes: proto.Clone(job.Hashes).(*p.JobHashes), observed: true}, nil
}
