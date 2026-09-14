package networkpolicy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrAuthority = errors.New("network_authority_invalid")

// Authority retains one immutable admitted job's current authority state. It is
// not stream authentication, offer admission, a timer, or installed enforcement.
// An owner must independently expire/withdraw its route and workload, and never
// restore this object from historical acknowledgement metadata after a restart.
type Authority struct {
	mu               sync.Mutex
	lease            *p.LeaseIdentity
	attempt          *p.AttemptIdentity
	policy           *p.NetworkPolicyV2
	digest           [sha256.Size]byte
	checked, expires time.Time
	seen, withdrawn  bool
}

// NewAuthority validates the complete frozen policy identity and copies the
// owning job/lease/attempt. Construction grants no network permission.
func NewAuthority(job *p.JobSpecification) (*Authority, error) {
	if job == nil || job.Lease == nil || job.Attempt == nil || !validAuthorityLease(job.Lease) || !validAuthorityAttempt(job.Attempt) {
		return nil, ErrAuthority
	}
	digest, err := EffectivePolicyV2SHA256(job.EffectivePolicy)
	claimed := job.GetHashes().GetPolicy()
	if err != nil || claimed == nil || !closedWireV2(claimed.ProtoReflect()) || claimed.Algorithm != p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 || !bytes.Equal(digest[:], claimed.Value) {
		return nil, ErrAuthority
	}
	return &Authority{lease: proto.Clone(job.Lease).(*p.LeaseIdentity), attempt: proto.Clone(job.Attempt).(*p.AttemptIdentity), policy: proto.Clone(job.EffectivePolicy.NetworkV2).(*p.NetworkPolicyV2), digest: digest}, nil
}

func validAuthorityID(id string) bool {
	return jobID.MatchString(id) && id != "00000000-0000-0000-0000-000000000000"
}
func validAuthorityLease(lease *p.LeaseIdentity) bool {
	return lease != nil && closedWireV2(lease.ProtoReflect()) && validAuthorityID(lease.LeaseId) && validAuthorityID(lease.JobId) && validAuthorityID(lease.ExecutionId) && validAuthorityTime(lease.ExpiresAt)
}
func validAuthorityAttempt(attempt *p.AttemptIdentity) bool {
	return attempt != nil && closedWireV2(attempt.ProtoReflect()) && validAuthorityID(attempt.AttemptId) && validAuthorityID(attempt.ReleaseCandidateId) && validAuthorityID(attempt.MatrixEntryId) && attempt.AttemptNumber >= 1 && attempt.AttemptNumber <= 3
}
func validAuthorityTime(value *timestamppb.Timestamp) bool {
	return value != nil && value.CheckValid() == nil && len(value.ProtoReflect().GetUnknown()) == 0
}

func authorityFeatures(features []p.ProtocolFeature) (bool, error) {
	seen := [11]bool{}
	for _, feature := range features {
		if feature < 1 || feature > 10 || seen[feature] {
			return false, ErrAuthority
		}
		seen[feature] = true
	}
	if seen[10] && (!seen[1] || !seen[3] || !seen[9]) {
		return false, ErrAuthority
	}
	return seen[10], nil
}

// Reconcile consumes a separately authenticated, identity-matched acknowledgement
// and the current stream's negotiated features/credential deadline. Disposition
// STALE is intentionally not a revocation signal. An error irreversibly withdraws
// this attempt, as do terminality, explicit withdrawal and observed expiry.
func (a *Authority) Reconcile(reconciliation *p.LeaseReconciliation, features []p.ProtocolFeature, credentialExpiry, now time.Time) error {
	if a == nil {
		return ErrAuthority
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	reject := func() error { a.withdrawn = true; return ErrAuthority }
	negotiated, err := authorityFeatures(features)
	if err != nil || a.lease == nil || a.attempt == nil || a.policy == nil || now.IsZero() || !timestamppb.New(now).IsValid() || !timestamppb.New(credentialExpiry).IsValid() || reconciliation == nil || !closedWireV2(reconciliation.ProtoReflect()) || !validAuthorityLease(reconciliation.Lease) || !validAuthorityAttempt(reconciliation.Attempt) {
		return reject()
	}
	lease := reconciliation.Lease
	if lease.LeaseId != a.lease.LeaseId || lease.JobId != a.lease.JobId || lease.ExecutionId != a.lease.ExecutionId || !proto.Equal(reconciliation.Attempt, a.attempt) {
		return reject()
	}
	status := reconciliation.Status
	if status < p.LeaseStatus_LEASE_STATUS_OFFERED || status > p.LeaseStatus_LEASE_STATUS_RELEASED {
		return reject()
	}
	observation := reconciliation.NetworkAuthorityV2
	cancelling := reconciliation.CancellationId != "" || reconciliation.Phase == p.JobPhase_JOB_PHASE_CANCELLING
	needs := a.policy.Mode != p.NetworkMode_NETWORK_MODE_NONE && (status == p.LeaseStatus_LEASE_STATUS_ACCEPTED || status == p.LeaseStatus_LEASE_STATUS_ACTIVE) && !cancelling
	if !needs {
		if observation != nil {
			return reject()
		}
		if cancelling || status >= p.LeaseStatus_LEASE_STATUS_COMPLETED {
			a.withdrawn = true
		}
		return nil
	}
	if !negotiated || observation == nil || !closedWireV2(observation.ProtoReflect()) || observation.Policy == nil || observation.Policy.Algorithm != p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 || !bytes.Equal(observation.Policy.Value, a.digest[:]) || !validAuthorityTime(observation.CheckedAt) {
		return reject()
	}
	checked := observation.CheckedAt.AsTime()
	if checked.After(now.Add(5 * time.Second)) {
		return reject()
	}
	switch observation.State {
	case p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_WITHDRAWN:
		if observation.ExpiresAt != nil {
			return reject()
		}
		a.withdrawn = true
		return nil
	case p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT:
	default:
		return reject()
	}
	if !validAuthorityTime(observation.ExpiresAt) {
		return reject()
	}
	expires := observation.ExpiresAt.AsTime()
	leaseExpiry := a.lease.ExpiresAt.AsTime()
	if lease.ExpiresAt.AsTime().After(leaseExpiry) {
		leaseExpiry = lease.ExpiresAt.AsTime()
	}
	if !expires.After(now) || !expires.After(checked) || expires.After(checked.Add(time.Minute)) || expires.After(leaseExpiry) || expires.After(credentialExpiry) {
		return reject()
	}
	// Lease state is independently acknowledged even when this message carries
	// an older still-valid authority check that must not extend its deadline.
	a.lease.ExpiresAt = timestamppb.New(leaseExpiry)
	if a.withdrawn {
		return nil
	}
	if a.seen {
		if !a.expires.After(now) {
			a.withdrawn = true
			return nil
		}
		if checked.Equal(a.checked) && !expires.Equal(a.expires) {
			return reject()
		}
		if !checked.After(a.checked) {
			// Keeping an older observation must not retain permission beyond a
			// shorter credential on the newly authenticated stream. Refuse,
			// rather than repair, authority that this stream cannot sustain.
			if a.expires.After(credentialExpiry) {
				return reject()
			}
			return nil
		}
	}
	a.checked, a.expires, a.seen = checked, expires, true
	return nil
}

// Deadline is a current observation only. Callers must enforce it independently
// in kernel/DNS lifetimes; polling this method is not a substitute for teardown.
func (a *Authority) Deadline(now time.Time) (time.Time, error) {
	if a == nil {
		return time.Time{}, ErrAuthority
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deadlineLocked(now)
}

func (a *Authority) deadlineLocked(now time.Time) (time.Time, error) {
	if now.IsZero() || a.withdrawn || !a.seen {
		return time.Time{}, ErrAuthority
	}
	if !a.expires.After(now) {
		a.withdrawn = true
		return time.Time{}, ErrExpired
	}
	return a.expires, nil
}

func (a *Authority) Withdraw() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.withdrawn = true
	a.mu.Unlock()
}

// ConstrainBindings copies validated DNS bindings and bounds their lifetime by
// current authority. It refuses changed grants/caps or missing/duplicate hosts.
// It does not install or refresh a route, and cannot revive withdrawn authority.
func (a *Authority) ConstrainBindings(bindings []Binding, now time.Time) ([]Binding, error) {
	if a == nil {
		return nil, ErrAuthority
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	deadline, err := a.deadlineLocked(now)
	if err != nil {
		return nil, err
	}
	reject := func() ([]Binding, error) { a.withdrawn = true; return nil, ErrAuthority }
	expected := make(map[string][]Permission)
	for _, grant := range a.policy.Permissions {
		transport := "tcp"
		if grant.Transport == p.NetworkTransportV2_NETWORK_TRANSPORT_V2_UDP {
			transport = "udp"
		}
		expected[grant.Hostname] = append(expected[grant.Hostname], Permission{Hostname: grant.Hostname, Port: uint16(grant.Port), Protocol: transport})
	}
	if len(bindings) != len(expected) {
		return reject()
	}
	result := make([]Binding, 0, len(bindings))
	for _, binding := range bindings {
		grants, exists := expected[binding.hostname]
		if !exists || binding.job != a.lease.JobId || !binding.ValidAt(now) || binding.limits != (Limits{Connections: uint64(a.policy.MaximumConnections), BytesPerSecond: uint64(a.policy.MaximumBytesPerSecond)}) || len(grants) != len(binding.permissions) {
			return reject()
		}
		for index, grant := range grants {
			if binding.permissions[index] != grant {
				return reject()
			}
		}
		delete(expected, binding.hostname)
		binding.addresses = binding.Addresses()
		binding.permissions = binding.Permissions()
		if deadline.Before(binding.expires) {
			binding.expires = deadline
		}
		result = append(result, binding)
	}
	return result, nil
}
