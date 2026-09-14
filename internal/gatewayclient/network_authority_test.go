package gatewayclient

import (
	"bytes"
	"context"
	"testing"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func authoritySessionFixture(t *testing.T) (*clientSession, *p.JobSpecification, *p.LeaseReconciliation, *[]*p.RunnerMessage) {
	t.Helper()
	c, job, _ := networkAuthorityWorkerFixture(t)
	now := time.Now().UTC()
	ctx, cancel := context.WithCancel(context.Background())
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	var sent []*p.RunnerMessage
	s := &clientSession{client: c, rootContext: ctx, authenticated: authenticated, networkFeatures: []p.ProtocolFeature{1, 3, 9, 10}, generation: 1, send: func(message *p.RunnerMessage) error {
		sent = append(sent, proto.Clone(message).(*p.RunnerMessage))
		return nil
	}}
	t.Cleanup(func() {
		cancel()
		if c.workerNetworkAuthority != nil {
			if err := c.workerNetworkAuthority.Close(); err != nil {
				t.Error(err)
			}
		}
		c.workerWG.Wait()
	})
	r := &p.LeaseReconciliation{Lease: proto.Clone(job.Lease).(*p.LeaseIdentity), Attempt: proto.Clone(job.Attempt).(*p.AttemptIdentity), Status: p.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: p.JobPhase_JOB_PHASE_RUNNING, Disposition: p.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE,
		NetworkAuthorityV2: &p.NetworkAuthorityV2{Policy: proto.Clone(job.Hashes.Policy).(*p.Digest), State: p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT, CheckedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second))}}
	return s, job, r, &sent
}

func authorityHeartbeat(t *testing.T, s *clientSession, r *p.LeaseReconciliation) *p.HeartbeatAcknowledgement {
	t.Helper()
	now := time.Now().UTC()
	if err := s.sendHeartbeat(now); err != nil {
		t.Fatal(err)
	}
	m := s.pendingHeartbeat
	return &p.HeartbeatAcknowledgement{RunnerMessageId: m.MessageId, Sequence: m.GetHeartbeat().Sequence, CommittedAt: timestamppb.New(now), Reconciliations: []*p.LeaseReconciliation{proto.Clone(r).(*p.LeaseReconciliation)}}
}

func TestNetworkAuthorityHeartbeatOwnsFreshGuardAndStaleLeaseOrdering(t *testing.T) {
	s, job, r, _ := authoritySessionFixture(t)
	ack := authorityHeartbeat(t, s, r)
	if err := s.handleHeartbeatAcknowledgement(ack, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	guard := s.client.workerNetworkAuthority
	if guard == nil || guard.CheckJob(job) != nil {
		t.Fatal("fresh heartbeat did not own a guard")
	}
	before := s.client.journal.snapshot().Active.Specification
	// Replay is matched to the remembered heartbeat. An old receipt expiry
	// cannot regress independently acknowledged durable lease state.
	ack.Reconciliations[0].Lease.ExpiresAt = timestamppb.New(time.Now().Add(-time.Second))
	ack.Reconciliations[0].NetworkAuthorityV2.CheckedAt = timestamppb.New(time.Now())
	ack.Reconciliations[0].NetworkAuthorityV2.ExpiresAt = timestamppb.New(time.Now().Add(35 * time.Second))
	if err := s.handleHeartbeatAcknowledgement(ack, time.Now().UTC()); err != nil {
		t.Fatal("old heartbeat invalidated renewal", err)
	}
	if s.client.workerNetworkAuthority != guard || guard.CheckJob(job) != nil || !bytes.Equal(before, s.client.journal.snapshot().Active.Specification) {
		t.Fatal("replay changed job identity or revived another guard")
	}
}

func TestNetworkAuthorityWithdrawalBeforeWorkerQueuesOnlyOwningFailure(t *testing.T) {
	s, job, r, sent := authoritySessionFixture(t)
	now := time.Now().UTC()
	if err := s.queueDurable(&p.RunnerMessage_LeaseAccepted{LeaseAccepted: &p.LeaseAccepted{Lease: job.Lease, Attempt: job.Attempt, AcceptedAt: timestamppb.New(now)}}, func(state *journalState) error { state.Active.Phase = p.JobPhase_JOB_PHASE_ACCEPTED; return nil }); err != nil {
		t.Fatal(err)
	}
	pending := (*sent)[0]
	r.Status = p.LeaseStatus_LEASE_STATUS_ACCEPTED
	r.Phase = p.JobPhase_JOB_PHASE_ACCEPTED
	r.NetworkAuthorityV2.State = p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_WITHDRAWN
	r.NetworkAuthorityV2.ExpiresAt = nil
	ack := &p.RunnerEventAcknowledgement{RunnerMessageId: pending.MessageId, CommittedAt: timestamppb.New(now), Reconciliation: r}
	if err := s.handleEventAcknowledgement(ack, now); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2 || (*sent)[1].GetFailed().GetFailure().GetCode() != "network_authority_lost" || (*sent)[1].GetCancelled() != nil {
		t.Fatal("withdrawal did not queue ordinary failure")
	}
	if state := s.client.journal.snapshot(); state.Active == nil || state.Active.CancellationID != "" || len(state.PendingMessage) == 0 || s.client.isWorkerRunning() {
		t.Fatal("withdrawal released ownership or started worker")
	}
	// Terminal acknowledgement can settle normally without current authority.
	terminal := eventAcknowledgement(now, "network-terminal", (*sent)[1], p.LeaseStatus_LEASE_STATUS_COMPLETED, p.JobPhase_JOB_PHASE_UNSPECIFIED).GetEventAcknowledgement()
	if err := s.handleEventAcknowledgement(terminal, now); err != nil {
		t.Fatal(err)
	}
	if s.client.journal.snapshot().Active != nil {
		t.Fatal("owning terminal acknowledgement did not settle")
	}
}

func TestNetworkAuthorityMalformedReplayWithdrawsWithoutJournalAdvance(t *testing.T) {
	s, _, r, _ := authoritySessionFixture(t)
	ack := authorityHeartbeat(t, s, r)
	if err := s.handleHeartbeatAcknowledgement(ack, time.Now()); err != nil {
		t.Fatal(err)
	}
	before := s.client.journal.snapshot().Active.Specification
	ack.Reconciliations[0].NetworkAuthorityV2.Policy.Value[0]++
	ack.Reconciliations[0].Lease.ExpiresAt = timestamppb.New(time.Now().Add(time.Hour))
	if err := s.handleHeartbeatAcknowledgement(ack, time.Now()); err == nil {
		t.Fatal("invalid replay accepted")
	}
	if !s.client.networkAuthorityStopped() || !bytes.Equal(before, s.client.journal.snapshot().Active.Specification) {
		t.Fatal("invalid replay retained permission or advanced journal")
	}
	// A valid later receipt may settle failure, never revive the guard.
	ack.Reconciliations[0] = r
	if err := s.handleHeartbeatAcknowledgement(ack, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !s.client.networkAuthorityStopped() {
		t.Fatal("positive receipt revived stopped attempt")
	}
}

func TestNetworkAuthorityReconnectAndRecoveryNeverRevive(t *testing.T) {
	s, _, r, _ := authoritySessionFixture(t)
	if err := s.consumeNetworkAuthority(r); err != nil {
		t.Fatal(err)
	}
	guard := s.client.workerNetworkAuthority
	s.client.stopNetworkAuthority(99)
	if s.client.networkAuthorityStopped() {
		t.Fatal("foreign generation stopped current guard")
	}
	s.client.stopNetworkAuthority(1)
	s.generation = 2
	if err := s.consumeNetworkAuthority(r); err != nil {
		t.Fatal(err)
	}
	if s.client.workerNetworkAuthority != guard || !s.client.networkAuthorityStopped() {
		t.Fatal("reconnect revived guard")
	}
	s.networkFeatures = []p.ProtocolFeature{1, 3, 9}
	if err := s.consumeNetworkAuthority(r); err == nil {
		t.Fatal("downgrade accepted")
	}
	recovered, _, current, _ := authoritySessionFixture(t)
	recovered.client.recovering = true
	if err := recovered.consumeNetworkAuthority(current); err != nil {
		t.Fatal(err)
	}
	if recovered.client.workerNetworkAuthority != nil {
		t.Fatal("restart rebuilt authority from receipt")
	}
}

func TestNetworkAuthorityUnexpectedAndForeignAcknowledgementsRefused(t *testing.T) {
	for _, kind := range []string{"legacy", "foreign", "missing", "sequence"} {
		t.Run(kind, func(t *testing.T) {
			s, job, r, _ := authoritySessionFixture(t)
			if kind == "legacy" {
				job.EffectivePolicy.NetworkV2 = nil
				encoded, _ := proto.Marshal(job)
				if err := s.client.journal.update(func(state *journalState) error { state.Active.Specification = encoded; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			ack := authorityHeartbeat(t, s, r)
			switch kind {
			case "foreign":
				ack.Reconciliations[0].Attempt.AttemptNumber++
			case "missing":
				ack.Reconciliations[0].NetworkAuthorityV2 = nil
			case "sequence":
				ack.Sequence++
			}
			if err := s.handleHeartbeatAcknowledgement(ack, time.Now()); err == nil {
				t.Fatal("invalid acknowledgement accepted")
			}
			if s.pendingHeartbeat == nil {
				t.Fatal("invalid acknowledgement settled pending heartbeat")
			}
			if kind != "missing" && s.client.workerNetworkAuthority != nil {
				t.Fatal("unmatched acknowledgement created guard")
			}
		})
	}
}

func TestNetworkAuthorityNewAttemptRequiresFreshGuardAfterOwnedCleanup(t *testing.T) {
	s, job, r, _ := authoritySessionFixture(t)
	if err := s.consumeNetworkAuthority(r); err != nil {
		t.Fatal(err)
	}
	previous := s.client.workerNetworkAuthority
	s.client.stopNetworkAuthority(0)
	// A distinct admitted retry may get its own guard; this never resumes the
	// old attempt. The original policy bytes remain unchanged.
	job.Attempt.AttemptNumber++
	job.Attempt.AttemptId = "90000000-0000-4000-8000-000000000001"
	job.Lease.LeaseId = "90000000-0000-4000-8000-000000000002"
	encoded, err := proto.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.client.journal.update(func(state *journalState) error { state.Active.Specification = encoded; return nil }); err != nil {
		t.Fatal(err)
	}
	r.Lease = job.Lease
	r.Attempt = job.Attempt
	if err := s.consumeNetworkAuthority(r); err != nil {
		t.Fatal(err)
	}
	if s.client.workerNetworkAuthority == previous || s.client.workerNetworkAuthority.CheckJob(job) != nil {
		t.Fatal("fresh attempt did not get independent authority")
	}
	select {
	case <-previous.Done():
	default:
		t.Fatal("old attempt revived")
	}
}

func TestNetworkAuthorityWorkerStopWithdrawsBeforeResult(t *testing.T) {
	s, _, r, _ := authoritySessionFixture(t)
	if err := s.consumeNetworkAuthority(r); err != nil {
		t.Fatal(err)
	}
	cancelled := false
	s.client.workerCancel = func() { cancelled = true }
	s.client.stopWorker(context.Canceled)
	if !cancelled || !s.client.networkAuthorityStopped() {
		t.Fatal("worker cancellation did not withdraw authority")
	}
	if s.client.journal.snapshot().Active == nil {
		t.Fatal("worker stop claimed terminal settlement")
	}
}
