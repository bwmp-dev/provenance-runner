package gatewayclient

import (
	"context"
	"errors"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func enabledNetworkJob(job *p.JobSpecification) bool {
	policy := job.GetEffectivePolicy().GetNetworkV2()
	return policy != nil && policy.Mode != p.NetworkMode_NETWORK_MODE_NONE
}

// Called only after the enclosing authenticated acknowledgement's pending or
// remembered identity, cardinality, sequence and normal reconciliation checks.
// No observation is journaled or reconstructed as a grant after process restart.
func (s *clientSession) consumeNetworkAuthority(value *p.LeaseReconciliation) error {
	state := s.client.journal.snapshot()
	if state.Active == nil || !activeMatchesIdentity(state.Active, value.GetLease(), value.GetAttempt()) {
		if value.GetNetworkAuthorityV2() != nil {
			return permanent("network authority has no matching active attempt")
		}
		return nil
	}
	job := new(p.JobSpecification)
	if proto.Unmarshal(state.Active.Specification, job) != nil {
		return permanent("network authority active identity is invalid")
	}
	if !enabledNetworkJob(job) {
		if value.GetNetworkAuthorityV2() != nil {
			return permanent("unexpected network authority for legacy or none job")
		}
		return nil
	}
	cleanup := terminalLeaseStatus(value.GetStatus()) || value.GetCancellationId() != "" || value.GetPhase() == p.JobPhase_JOB_PHASE_CANCELLING || value.GetStatus() == p.LeaseStatus_LEASE_STATUS_OFFERED
	if cleanup {
		if value.GetNetworkAuthorityV2() != nil {
			s.client.stopNetworkAuthority(0)
			return permanent("unexpected network authority during cleanup")
		}
		s.client.stopNetworkAuthority(0)
		return nil
	}
	if s.authenticated == nil || !advertisedFeature(s.networkFeatures, p.ProtocolFeature_PROTOCOL_FEATURE_NETWORK_AUTHORITY_V2) {
		s.client.stopNetworkAuthority(0)
		return errors.New("enabled job requires current stream network authority")
	}
	if s.client.recovering {
		// Validate delivery, but never build a resumed guard from a recovered
		// journal. The established restart-failure path owns reconciliation.
		check, err := networkpolicy.NewAuthority(job)
		if err != nil {
			return errors.New("recovered network identity is invalid")
		}
		if err := check.Reconcile(value, s.networkFeatures, s.authenticated.GetCredentialExpiresAt().AsTime(), time.Now()); err != nil {
			return errors.New("recovered network authority is invalid")
		}
		return nil
	}
	c := s.client
	c.workerMu.Lock()
	guard := c.workerNetworkAuthority
	previous := c.workerNetworkJob
	if guard != nil && (previous == nil || !sameLeaseAttempt(previous.Lease, previous.Attempt, job.Lease, job.Attempt)) {
		if c.workerRunning {
			c.workerMu.Unlock()
			return errors.New("prior network attempt cleanup is still running")
		}
		if err := guard.Close(); err != nil {
			c.workerMu.Unlock()
			c.Drain()
			return errors.New("prior network attempt cleanup is unproven")
		}
		guard = nil
	}
	if guard == nil {
		ctx := s.rootContext
		if ctx == nil {
			ctx = context.Background()
		}
		var err error
		guard, err = networkpolicy.NewAuthorityRoute(ctx, job)
		if err != nil {
			c.workerMu.Unlock()
			return errors.New("network authority job identity is invalid")
		}
		c.workerNetworkAuthority = guard
		c.workerNetworkJob = proto.Clone(job).(*p.JobSpecification)
	}
	c.workerNetworkGeneration = s.generation
	c.workerMu.Unlock()
	ctx := s.rootContext
	if ctx == nil {
		ctx = context.Background()
	}
	err := guard.Reconcile(ctx, value, s.networkFeatures, s.authenticated.GetCredentialExpiresAt().AsTime())
	if err != nil && !errors.Is(err, networkpolicy.ErrAuthorityWithdrawn) {
		return errors.New("network authority reconciliation rejected")
	}
	return nil
}

// A lost stream permanently withdraws its attempt. A later stream can still
// settle normal terminal bookkeeping, but cannot revive this in-memory guard.
func (c *Client) stopNetworkAuthority(generation uint64) {
	c.workerMu.Lock()
	guard := c.workerNetworkAuthority
	if generation != 0 && generation != c.workerNetworkGeneration {
		guard = nil
	}
	c.workerMu.Unlock()
	if guard != nil {
		_ = guard.Withdraw()
	}
}

func (c *Client) networkAuthorityStopped() bool {
	c.workerMu.Lock()
	defer c.workerMu.Unlock()
	if c.workerNetworkAuthority == nil {
		return false
	}
	state := c.journal.snapshot()
	if state.Active == nil || c.workerNetworkJob == nil || !activeMatchesIdentity(state.Active, c.workerNetworkJob.Lease, c.workerNetworkJob.Attempt) {
		return false
	}
	select {
	case <-c.workerNetworkAuthority.Done():
		return true
	default:
		return false
	}
}

// Only before worker invocation (or after all deferred worker results drained).
// Withdrawal itself never synthesizes cancellation or a cleanup success claim.
func (s *clientSession) queueNetworkAuthorityFailure(now time.Time) error {
	c := s.client
	c.workerMu.Lock()
	guard := c.workerNetworkAuthority
	running := c.workerRunning
	c.workerMu.Unlock()
	if guard == nil || running {
		return nil
	}
	code, summary, stage := "network_authority_lost", "network authority unavailable before execution", p.FailureStage_FAILURE_STAGE_PREPARATION
	if err := guard.Close(); err != nil {
		c.Drain()
		code = "network_cleanup_failed"
		summary = "owned network teardown could not be proven"
		stage = p.FailureStage_FAILURE_STAGE_CLEANUP
	}
	lease, attempt, err := activeIdentity(c.journal.snapshot())
	if err != nil {
		return err
	}
	failed := &p.JobFailed{Lease: lease, Attempt: attempt, FailedAt: timestamppb.New(normalizedTerminalTime(now)), Failure: &p.FailureDetail{Category: p.FailureCategory_FAILURE_CATEGORY_INFRASTRUCTURE, Stage: stage, Code: code, Summary: summary, Retryable: true}}
	return s.queueDurable(&p.RunnerMessage_Failed{Failed: failed}, nil)
}
