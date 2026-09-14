package gatewayclient

import (
	"context"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type authorityWaitingWorker struct {
	entered chan *networkpolicy.AuthorityRoute
}

func (w *authorityWaitingWorker) Execute(context.Context, *p.JobSpecification, func(context.Context, execution.ExecutionStart) error) execution.Result {
	panic("legacy worker selected for network v2")
}
func (w *authorityWaitingWorker) ExecuteV2(ctx context.Context, _ *p.JobSpecification, _ func(context.Context, execution.ExecutionStart) error) execution.Result {
	w.entered <- execution.NetworkAuthorityRoute(ctx)
	<-ctx.Done()
	return execution.Result{Status: "failed", Phase: execution.PhasePreparation, Classification: execution.ClassificationCancelled, StartedAt: time.Now().UTC(), CompletedAt: time.Now().UTC(), Cleanup: &execution.CleanupResult{Attempted: true, Succeeded: true}}
}

func networkAuthorityWorkerFixture(t *testing.T) (*Client, *p.JobSpecification, *networkpolicy.AuthorityRoute) {
	t.Helper()
	now := time.Now().UTC()
	c, offer := activeEvidenceClient(t, now)
	job := proto.Clone(offer.Job).(*p.JobSpecification)
	job.CompleteLogUpload = nil
	job.EffectivePolicy.Network = nil
	job.EffectivePolicy.NetworkV2 = &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_ALLOWLIST, MaximumConnections: 16, MaximumBytesPerSecond: 65536, Permissions: []*p.NetworkPermissionV2{{Hostname: "fixture.example.com", Port: 8080, Transport: p.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP}}}
	digest, err := networkpolicy.EffectivePolicyV2SHA256(job.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Policy = &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}
	encoded, err := proto.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.journal.update(func(s *journalState) error {
		s.Active.Specification = encoded
		s.Active.TerminalEvidenceV2 = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	guard, err := networkpolicy.NewAuthorityRoute(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := guard.Close(); err != nil {
			t.Error(err)
		}
	})
	receipt := &p.LeaseReconciliation{Lease: job.Lease, Attempt: job.Attempt, Status: p.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: p.JobPhase_JOB_PHASE_RUNNING, Disposition: p.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE, NetworkAuthorityV2: &p.NetworkAuthorityV2{Policy: job.Hashes.Policy, State: p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT, CheckedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second))}}
	if err := guard.Reconcile(context.Background(), receipt, []p.ProtocolFeature{1, 3, 9, 10}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	return c, job, guard
}

func TestNetworkWorkerWithoutFreshGuardNeverInvokesProvider(t *testing.T) {
	c, _, _ := networkAuthorityWorkerFixture(t)
	w := &authorityWaitingWorker{entered: make(chan *networkpolicy.AuthorityRoute, 1)}
	c.worker = w
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.startWorker(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-c.workerEvents:
		if event.result == nil || event.result.Failure.Code != "network_authority_lost" {
			t.Fatal("missing guard failure lost")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("guardless worker hung")
	}
	c.workerWG.Wait()
	select {
	case <-w.entered:
		t.Fatal("guardless provider invoked")
	default:
	}
	if c.journal.snapshot().Active.CancellationID != "" {
		t.Fatal("authority failure invented cancellation")
	}
}

func TestNetworkWorkerUsesOwningGuardAndReportsOrdinaryFailure(t *testing.T) {
	c, _, guard := networkAuthorityWorkerFixture(t)
	c.workerNetworkAuthority = guard
	w := &authorityWaitingWorker{entered: make(chan *networkpolicy.AuthorityRoute, 1)}
	c.worker = w
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.startWorker(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-w.entered:
		if got != guard {
			t.Fatal("wrong guard")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not start")
	}
	if err := guard.Withdraw(); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-c.workerEvents:
		if event.result == nil || event.result.Classification != execution.ClassificationInfrastructureFailure || event.result.Failure.Code != "network_authority_lost" || event.result.Cleanup == nil || !event.result.Cleanup.Succeeded {
			t.Fatal("ordinary network failure/cleanup lost")
		}
		var terminal *p.RunnerMessage
		session := &clientSession{client: c, rootContext: ctx, send: func(value *p.RunnerMessage) error { terminal = value; return nil }}
		if err := session.handleWorkerEvent(event); err != nil {
			t.Fatal(err)
		}
		if terminal.GetFailed() == nil || terminal.GetCancelled() != nil || terminal.GetFailed().GetFailure().GetCode() != "network_authority_lost" {
			t.Fatal("authority failure did not follow ordinary failed event path")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker survived authority loss")
	}
	c.workerWG.Wait()
	if c.journal.snapshot().Active == nil || c.journal.snapshot().Active.CancellationID != "" {
		t.Fatal("worker result released active lease or invented cancellation")
	}
}
