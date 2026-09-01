package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type gatedWorker struct {
	preparing chan struct{}
	executed  chan struct{}
	now       time.Time
}

type cancellingWorker struct {
	started time.Time
}

func (w *cancellingWorker) Execute(ctx context.Context, _ *runnerv1.JobSpecification, beforeExecute func(context.Context, execution.ExecutionStart) error) execution.Result {
	if err := beforeExecute(ctx, execution.ExecutionStart{JobID: "job", Provider: "paper", EnvironmentIdentity: "paper"}); err != nil {
		return execution.FailedResult("job", execution.PhaseExecution, execution.ClassificationCancelled, "job_cancelled", err)
	}
	<-ctx.Done()
	return execution.Result{SchemaVersion: execution.ResultSchemaVersion, JobID: "job", Status: "failed", Classification: execution.ClassificationCancelled, Phase: execution.PhaseCleanup, Failure: execution.NewFailure(execution.ClassificationCancelled, "job_cancelled", ctx.Err().Error()), Cleanup: &execution.CleanupResult{Attempted: true, Succeeded: true}, StartedAt: w.started, CompletedAt: w.started}
}

func (w *gatedWorker) Execute(ctx context.Context, _ *runnerv1.JobSpecification, beforeExecute func(context.Context, execution.ExecutionStart) error) execution.Result {
	close(w.preparing)
	if err := beforeExecute(ctx, execution.ExecutionStart{JobID: "job", Provider: "paper", EnvironmentIdentity: "paper"}); err != nil {
		return execution.FailedResult("job", execution.PhaseExecution, execution.ClassificationInfrastructureFailure, "before_execute_failed", err)
	}
	close(w.executed)
	return execution.Result{SchemaVersion: execution.ResultSchemaVersion, JobID: "job", Status: "passed", Classification: execution.ClassificationPassed, Phase: execution.PhaseCompleted, StartedAt: w.now, CompletedAt: w.now}
}

func TestDurableOfferLifecycleDoesNotExecuteBeforeJobStartedAcknowledgement(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	worker := &gatedWorker{preparing: make(chan struct{}), executed: make(chan struct{}), now: now}
	offer := validLeaseOffer(now)
	serverResult := make(chan error, 1)
	server := &testGateway{connect: func(stream grpc.BidiStreamingServer[runnerv1.RunnerMessage, runnerv1.GatewayMessage]) (result error) {
		defer func() { serverResult <- result }()
		authenticate, err := stream.Recv()
		if err != nil || authenticate.GetAuthenticate() == nil {
			return errors.New("authenticate was not first")
		}
		authenticated := authenticatedMessage(now, platformScope())
		authenticated.GetAuthenticated().LeaseDuration = durationpb.New(10 * time.Minute)
		if err := stream.Send(authenticated); err != nil {
			return err
		}
		capabilities, err := stream.Recv()
		if err != nil || capabilities.GetCapabilities() == nil {
			return errors.New("capabilities were not second")
		}
		heartbeat, err := stream.Recv()
		if err != nil || heartbeat.GetHeartbeat() == nil {
			return errors.New("heartbeat was not third")
		}
		if err := stream.Send(uniqueGatewayMessage(now, "heartbeat-ack-1", &runnerv1.GatewayMessage_HeartbeatAcknowledgement{HeartbeatAcknowledgement: &runnerv1.HeartbeatAcknowledgement{RunnerMessageId: heartbeat.GetMessageId(), Sequence: heartbeat.GetHeartbeat().GetSequence(), CommittedAt: timestamppb.New(now)}})); err != nil {
			return err
		}
		if err := stream.Send(uniqueGatewayMessage(now, "offer-1", &runnerv1.GatewayMessage_Offer{Offer: offer})); err != nil {
			return err
		}
		accepted, err := stream.Recv()
		if err != nil || accepted.GetLeaseAccepted() == nil {
			return fmt.Errorf("lease acceptance was not sent: rejection=%#v message=%#v, %v", accepted.GetLeaseRejected(), accepted, err)
		}
		select {
		case <-worker.preparing:
			return errors.New("worker prepared before lease acceptance acknowledgement")
		default:
		}
		if err := stream.Send(eventAcknowledgement(now, "event-ack-accepted", accepted, runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED, runnerv1.JobPhase_JOB_PHASE_ACCEPTED)); err != nil {
			return err
		}
		preparing, err := stream.Recv()
		if err != nil || preparing.GetJobPreparing() == nil {
			return errors.New("job preparing was not sent")
		}
		if err := stream.Send(eventAcknowledgement(now, "event-ack-preparing", preparing, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_PREPARING)); err != nil {
			return err
		}
		select {
		case <-worker.preparing:
		case <-time.After(time.Second):
			return errors.New("worker did not begin preparation")
		}
		started, err := stream.Recv()
		if err != nil || started.GetJobStarted() == nil {
			return errors.New("job started was not sent")
		}
		select {
		case <-worker.executed:
			return errors.New("sandbox executed before job started acknowledgement")
		default:
		}
		if err := stream.Send(eventAcknowledgement(now, "event-ack-started", started, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_RUNNING)); err != nil {
			return err
		}
		select {
		case <-worker.executed:
		case <-time.After(time.Second):
			return errors.New("sandbox did not execute after job started acknowledgement")
		}
		completed, err := stream.Recv()
		if err != nil || completed.GetCompleted() == nil || completed.GetCompleted().GetResult().GetOutcome() != runnerv1.ResultOutcome_RESULT_OUTCOME_PASSED {
			return errors.New("deterministic completed result was not sent")
		}
		if err := stream.Send(eventAcknowledgement(now, "event-ack-completed", completed, runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED, runnerv1.JobPhase_JOB_PHASE_RUNNING)); err != nil {
			return err
		}
		return stream.Send(uniqueGatewayMessage(now, "shutdown", &runnerv1.GatewayMessage_Shutdown{Shutdown: &runnerv1.ShutdownRunner{ShutdownId: "shutdown", Deadline: timestamppb.New(now.Add(time.Minute))}}))
	}}
	client, closeConnection := bufconnClient(t, server)
	defer closeConnection()
	client.worker = worker
	client.config.Resources.CPUMillis = 2_000
	client.now = func() time.Time { return now }
	if err := client.Run(context.Background()); !errors.Is(err, ErrServerShutdown) {
		select {
		case serverErr := <-serverResult:
			t.Fatalf("Run() error = %v; server error = %v", err, serverErr)
		default:
			t.Fatalf("Run() error = %v", err)
		}
	}
	state := client.journal.snapshot()
	if state.Active != nil || len(state.PendingMessage) != 0 {
		t.Fatalf("terminal acknowledgement did not clear journal: %#v", state)
	}
}

func TestRecoveredLeaseFailsRetryablyOnlyWhenAuthoritativeAndClearsWhenStale(t *testing.T) {
	for _, test := range []struct {
		name        string
		disposition runnerv1.RunnerMessageDisposition
		status      runnerv1.LeaseStatus
		wantFailure bool
	}{
		{name: "authoritative", disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, wantFailure: true},
		{name: "stale", disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE, status: runnerv1.LeaseStatus_LEASE_STATUS_RELEASED},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
			client := newClient(validConfig(), nil)
			client.now = func() time.Time { return now }
			offer := validLeaseOffer(now)
			specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
			if err != nil {
				t.Fatal(err)
			}
			if err := client.journal.update(func(state *journalState) error {
				state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			client.recovering = true
			authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
			authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
			var sent []*runnerv1.RunnerMessage
			session := &clientSession{client: client, authenticated: authenticated, send: func(message *runnerv1.RunnerMessage) error {
				sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
				return nil
			}, rootContext: context.Background()}
			if err := session.sendHeartbeat(now); err != nil {
				t.Fatal(err)
			}
			heartbeat := session.pendingHeartbeat
			acknowledgement := &runnerv1.HeartbeatAcknowledgement{
				RunnerMessageId: heartbeat.GetMessageId(), Sequence: heartbeat.GetHeartbeat().GetSequence(), CommittedAt: timestamppb.New(now),
				Reconciliations: []*runnerv1.LeaseReconciliation{{Lease: proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), Disposition: test.disposition, Status: test.status, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING}},
			}
			if err := session.handleHeartbeatAcknowledgement(acknowledgement, now); err != nil {
				t.Fatal(err)
			}
			state := client.journal.snapshot()
			if test.wantFailure {
				if state.Active == nil || len(state.PendingMessage) == 0 || len(sent) != 2 {
					t.Fatalf("authoritative recovery state = %#v, sent %d", state, len(sent))
				}
				pending := new(runnerv1.RunnerMessage)
				if err := proto.Unmarshal(state.PendingMessage, pending); err != nil || pending.GetFailed().GetFailure().GetCode() != "runner_restarted" || !pending.GetFailed().GetFailure().GetRetryable() {
					t.Fatalf("restart failure = %#v, %v", pending.GetFailed(), err)
				}
			} else if state.Active != nil || len(state.PendingMessage) != 0 || len(sent) != 1 {
				t.Fatalf("stale recovery state = %#v, sent %d", state, len(sent))
			}
		})
	}
}

func TestReconnectReplaysPendingEventBeforeZeroLeaseHeartbeat(t *testing.T) {
	for _, test := range []struct {
		name    string
		phase   runnerv1.JobPhase
		payload func(*runnerv1.LeaseOffer, time.Time) any
		matches func(*runnerv1.RunnerMessage) bool
	}{
		{
			name:  "acceptance",
			phase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED,
			payload: func(offer *runnerv1.LeaseOffer, now time.Time) any {
				return &runnerv1.RunnerMessage_LeaseAccepted{LeaseAccepted: &runnerv1.LeaseAccepted{Lease: offer.GetJob().GetLease(), Attempt: offer.GetJob().GetAttempt(), AcceptedAt: timestamppb.New(now)}}
			},
			matches: func(message *runnerv1.RunnerMessage) bool { return message.GetLeaseAccepted() != nil },
		},
		{
			name:  "renewal",
			phase: runnerv1.JobPhase_JOB_PHASE_RUNNING,
			payload: func(offer *runnerv1.LeaseOffer, now time.Time) any {
				return &runnerv1.RunnerMessage_LeaseRenewal{LeaseRenewal: &runnerv1.LeaseRenewal{Lease: offer.GetJob().GetLease(), Attempt: offer.GetJob().GetAttempt(), RequestedExtension: durationpb.New(10 * time.Minute), ObservedAt: timestamppb.New(now)}}
			},
			matches: func(message *runnerv1.RunnerMessage) bool { return message.GetLeaseRenewal() != nil },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
			offer := validLeaseOffer(now)
			server := &testGateway{connect: func(stream grpc.BidiStreamingServer[runnerv1.RunnerMessage, runnerv1.GatewayMessage]) error {
				if _, err := stream.Recv(); err != nil {
					return err
				}
				authenticated := authenticatedMessage(now, platformScope())
				authenticated.GetAuthenticated().LeaseDuration = durationpb.New(10 * time.Minute)
				if err := stream.Send(authenticated); err != nil {
					return err
				}
				if _, err := stream.Recv(); err != nil {
					return err
				}
				replayed, err := stream.Recv()
				if err != nil || !test.matches(replayed) {
					return fmt.Errorf("pending %s event was not replayed first: %#v, %v", test.name, replayed, err)
				}
				heartbeat, err := stream.Recv()
				if err != nil || heartbeat.GetHeartbeat() == nil || len(heartbeat.GetHeartbeat().GetActiveLeases()) != 0 || heartbeat.GetHeartbeat().GetCapacity().GetAvailableJobs() != 0 {
					return fmt.Errorf("pending %s heartbeat was not zero-lease/busy: %#v, %v", test.name, heartbeat, err)
				}
				return stream.Send(uniqueGatewayMessage(now, "shutdown", &runnerv1.GatewayMessage_Shutdown{Shutdown: &runnerv1.ShutdownRunner{ShutdownId: "shutdown", Deadline: timestamppb.New(now.Add(time.Minute))}}))
			}}
			client, closeConnection := bufconnClient(t, server)
			defer closeConnection()
			client.now = func() time.Time { return now }
			specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
			if err != nil {
				t.Fatal(err)
			}
			pending := &runnerv1.RunnerMessage{MessageId: "000000000000000000000000-0000000000000001", SentAt: timestamppb.New(now)}
			switch payload := test.payload(offer, now).(type) {
			case *runnerv1.RunnerMessage_LeaseAccepted:
				pending.Payload = payload
			case *runnerv1.RunnerMessage_LeaseRenewal:
				pending.Payload = payload
			default:
				t.Fatal("unsupported test payload")
			}
			encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(pending)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.journal.update(func(state *journalState) error {
				state.MessageSequence = 1
				state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: test.phase, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
				state.PendingMessage = encoded
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := client.Run(context.Background()); !errors.Is(err, ErrServerShutdown) {
				t.Fatalf("Run() error = %v", err)
			}
		})
	}
}

func TestReconnectOldHeartbeatCannotInvalidateSettledRenewal(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := &runnerv1.RunnerMessage{MessageId: "000000000000000000000000-0000000000000001", SentAt: timestamppb.New(now), Payload: &runnerv1.RunnerMessage_Heartbeat{Heartbeat: &runnerv1.Heartbeat{Sequence: 1, Capacity: &runnerv1.Capacity{ConcurrentJobs: 1}, ActiveLeases: []*runnerv1.HeartbeatLease{{Lease: offer.GetJob().GetLease(), Attempt: offer.GetJob().GetAttempt(), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING}}, ObservedAt: timestamppb.New(now)}}}
	encodedHeartbeat, err := proto.MarshalOptions{Deterministic: true}.Marshal(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	renewal := &runnerv1.RunnerMessage{MessageId: "000000000000000000000000-0000000000000002", SentAt: timestamppb.New(now), Payload: &runnerv1.RunnerMessage_LeaseRenewal{LeaseRenewal: &runnerv1.LeaseRenewal{Lease: offer.GetJob().GetLease(), Attempt: offer.GetJob().GetAttempt(), RequestedExtension: durationpb.New(10 * time.Minute), ObservedAt: timestamppb.New(now)}}}
	encodedRenewal, err := proto.MarshalOptions{Deterministic: true}.Marshal(renewal)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.MessageSequence = 2
		state.HeartbeatSequence = 1
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		state.PendingMessage = encodedRenewal
		state.PendingHeartbeat = encodedHeartbeat
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{client: client, authenticated: authenticatedMessage(now, platformScope()).GetAuthenticated(), send: func(message *runnerv1.RunnerMessage) error {
		sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}, rootContext: context.Background()}
	if err := session.sendHeartbeat(now); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 0 || !session.heartbeatDeferred {
		t.Fatalf("old active heartbeat was not deferred: sent=%d deferred=%t", len(sent), session.heartbeatDeferred)
	}
	renewedLease := proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity)
	renewedLease.ExpiresAt = timestamppb.New(now.Add(10 * time.Minute))
	eventAck := &runnerv1.RunnerEventAcknowledgement{RunnerMessageId: renewal.GetMessageId(), Reconciliation: &runnerv1.LeaseReconciliation{Lease: renewedLease, Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_ALREADY_APPLIED, Status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING}, CommittedAt: timestamppb.New(now)}
	if err := session.handleEventAcknowledgement(eventAck, now); err != nil {
		t.Fatal(err)
	}
	if err := session.sendHeartbeat(now); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0].GetMessageId() != heartbeat.GetMessageId() {
		t.Fatalf("deferred heartbeat replay = %#v", sent)
	}
	stale := &runnerv1.LeaseReconciliation{Lease: proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE, Status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING}
	heartbeatAck := &runnerv1.HeartbeatAcknowledgement{RunnerMessageId: heartbeat.GetMessageId(), Sequence: heartbeat.GetHeartbeat().GetSequence(), Reconciliations: []*runnerv1.LeaseReconciliation{stale}, CommittedAt: timestamppb.New(now)}
	if err := session.handleHeartbeatAcknowledgement(heartbeatAck, now); err != nil {
		t.Fatal(err)
	}
	state := client.journal.snapshot()
	if state.Active == nil || !state.Active.ExpiresAt.Equal(now.Add(10*time.Minute)) || len(state.PendingHeartbeat) != 0 {
		t.Fatalf("stale old heartbeat invalidated settled renewal: %#v", state)
	}
}

func TestReconnectOldStaleHeartbeatCannotDiscardPendingAcceptance(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := &runnerv1.RunnerMessage{MessageId: "000000000000000000000000-0000000000000001", SentAt: timestamppb.New(now), Payload: &runnerv1.RunnerMessage_Heartbeat{Heartbeat: &runnerv1.Heartbeat{Sequence: 1, Capacity: &runnerv1.Capacity{ConcurrentJobs: 1}, ActiveLeases: []*runnerv1.HeartbeatLease{{Lease: offer.GetJob().GetLease(), Attempt: offer.GetJob().GetAttempt(), Phase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED}}, ObservedAt: timestamppb.New(now)}}}
	encodedHeartbeat, err := proto.MarshalOptions{Deterministic: true}.Marshal(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	accepted := &runnerv1.RunnerMessage{MessageId: "000000000000000000000000-0000000000000002", SentAt: timestamppb.New(now), Payload: &runnerv1.RunnerMessage_LeaseAccepted{LeaseAccepted: &runnerv1.LeaseAccepted{Lease: offer.GetJob().GetLease(), Attempt: offer.GetJob().GetAttempt(), AcceptedAt: timestamppb.New(now)}}}
	encodedAccepted, err := proto.MarshalOptions{Deterministic: true}.Marshal(accepted)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.MessageSequence = 2
		state.HeartbeatSequence = 1
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		state.PendingMessage = encodedAccepted
		state.PendingHeartbeat = encodedHeartbeat
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	session := &clientSession{client: client, authenticated: authenticatedMessage(now, platformScope()).GetAuthenticated(), send: func(*runnerv1.RunnerMessage) error { return nil }, rootContext: context.Background()}
	if err := session.sendHeartbeat(now); err != nil {
		t.Fatal(err)
	}
	stale := &runnerv1.LeaseReconciliation{Lease: proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE, Status: runnerv1.LeaseStatus_LEASE_STATUS_OFFERED, Phase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED}
	heartbeatAck := &runnerv1.HeartbeatAcknowledgement{RunnerMessageId: heartbeat.GetMessageId(), Sequence: 1, Reconciliations: []*runnerv1.LeaseReconciliation{stale}, CommittedAt: timestamppb.New(now)}
	if err := session.handleHeartbeatAcknowledgement(heartbeatAck, now); err != nil {
		t.Fatal(err)
	}
	state := client.journal.snapshot()
	if state.Active == nil || !bytes.Equal(state.PendingMessage, encodedAccepted) || len(state.PendingHeartbeat) != 0 {
		t.Fatalf("old stale heartbeat discarded pending acceptance: %#v", state)
	}
}

func TestPendingEventReplaysExactlyAndConflictingAcknowledgementFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.config.Resources.CPUMillis = 2_000
	client.worker = &gatedWorker{}
	client.now = func() time.Time { return now }
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	var sent [][]byte
	session := &clientSession{client: client, authenticated: authenticated, send: func(message *runnerv1.RunnerMessage) error {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			return err
		}
		sent = append(sent, encoded)
		return nil
	}, rootContext: context.Background()}
	offerMessage := uniqueGatewayMessage(now, "offer", &runnerv1.GatewayMessage_Offer{Offer: validLeaseOffer(now)})
	if err := session.handleOffer(offerMessage, now); err != nil {
		t.Fatal(err)
	}
	pending := client.journal.snapshot().PendingMessage
	if len(sent) != 1 || !bytes.Equal(sent[0], pending) {
		t.Fatal("accepted event did not persist exact bytes before send")
	}
	if err := session.replayPending(); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || !bytes.Equal(sent[1], pending) {
		t.Fatal("pending event replay changed serialized bytes")
	}
	accepted := new(runnerv1.RunnerMessage)
	if err := proto.Unmarshal(pending, accepted); err != nil {
		t.Fatal(err)
	}
	conflict := eventAcknowledgement(now, "bad-ack", accepted, runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED, runnerv1.JobPhase_JOB_PHASE_ACCEPTED).GetEventAcknowledgement()
	conflict.RunnerMessageId = "another-message"
	if err := session.handleEventAcknowledgement(conflict, now); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("conflicting acknowledgement error = %v", err)
	}
	if !bytes.Equal(client.journal.snapshot().PendingMessage, pending) {
		t.Fatal("conflicting acknowledgement mutated pending bytes")
	}
	skipped := eventAcknowledgement(now, "skipped-ack", accepted, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_RUNNING).GetEventAcknowledgement()
	if err := session.handleEventAcknowledgement(skipped, now); err == nil || !strings.Contains(err.Error(), "accepted status and phase") {
		t.Fatalf("phase-skipping acknowledgement error = %v", err)
	}
	state := client.journal.snapshot()
	if state.Active == nil || state.Active.Phase != runnerv1.JobPhase_JOB_PHASE_ACCEPTED || !bytes.Equal(state.PendingMessage, pending) {
		t.Fatalf("phase-skipping acknowledgement mutated state: %#v", state)
	}
}

func TestPendingEventAuthoritativeStateMatrix(t *testing.T) {
	tests := []struct {
		name        string
		pending     *runnerv1.RunnerMessage
		activePhase runnerv1.JobPhase
		disposition runnerv1.RunnerMessageDisposition
		status      runnerv1.LeaseStatus
		phase       runnerv1.JobPhase
		valid       bool
	}{
		{name: "accepted", pending: &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_LeaseAccepted{LeaseAccepted: &runnerv1.LeaseAccepted{}}}, activePhase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED, disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, status: runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED, phase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED, valid: true},
		{name: "accepted cannot skip", pending: &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_LeaseAccepted{LeaseAccepted: &runnerv1.LeaseAccepted{}}}, activePhase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED, disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, phase: runnerv1.JobPhase_JOB_PHASE_RUNNING},
		{name: "preparing", pending: &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_JobPreparing{JobPreparing: &runnerv1.JobPreparing{}}}, activePhase: runnerv1.JobPhase_JOB_PHASE_PREPARING, disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_ALREADY_APPLIED, status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, phase: runnerv1.JobPhase_JOB_PHASE_PREPARING, valid: true},
		{name: "preparing cannot skip", pending: &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_JobPreparing{JobPreparing: &runnerv1.JobPreparing{}}}, activePhase: runnerv1.JobPhase_JOB_PHASE_PREPARING, disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, phase: runnerv1.JobPhase_JOB_PHASE_RUNNING},
		{name: "started", pending: &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_JobStarted{JobStarted: &runnerv1.JobStarted{}}}, activePhase: runnerv1.JobPhase_JOB_PHASE_RUNNING, disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, valid: true},
		{name: "renewal current phase", pending: &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_LeaseRenewal{LeaseRenewal: &runnerv1.LeaseRenewal{}}}, activePhase: runnerv1.JobPhase_JOB_PHASE_RUNNING, disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, valid: true},
		{name: "renewal phase mismatch", pending: &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_LeaseRenewal{LeaseRenewal: &runnerv1.LeaseRenewal{}}}, activePhase: runnerv1.JobPhase_JOB_PHASE_RUNNING, disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, phase: runnerv1.JobPhase_JOB_PHASE_PREPARING},
		{name: "terminal", pending: &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_Completed{Completed: &runnerv1.JobCompleted{}}}, activePhase: runnerv1.JobPhase_JOB_PHASE_RUNNING, disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, status: runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED, phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, valid: true},
		{name: "terminal pending cannot remain active", pending: &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_Failed{Failed: &runnerv1.JobFailed{}}}, activePhase: runnerv1.JobPhase_JOB_PHASE_RUNNING, disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, phase: runnerv1.JobPhase_JOB_PHASE_RUNNING},
		{name: "stale exception", pending: &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_JobStarted{JobStarted: &runnerv1.JobStarted{}}}, activePhase: runnerv1.JobPhase_JOB_PHASE_RUNNING, disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE, status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, phase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED, valid: true},
		{name: "terminal race exception", pending: &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_LeaseAccepted{LeaseAccepted: &runnerv1.LeaseAccepted{}}}, activePhase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED, disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_ALREADY_APPLIED, status: runnerv1.LeaseStatus_LEASE_STATUS_CANCELLED, phase: runnerv1.JobPhase_JOB_PHASE_CANCELLING, valid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reconciliation := &runnerv1.LeaseReconciliation{Disposition: test.disposition, Status: test.status, Phase: test.phase}
			err := validatePendingReconciliation(test.pending, reconciliation, journalState{Active: &journalJob{Phase: test.activePhase}})
			if (err == nil) != test.valid {
				t.Fatalf("validatePendingReconciliation() error = %v, valid = %t", err, test.valid)
			}
		})
	}
}

func TestCancellationCommandIsIdempotentAcrossReconnectAndPayloadConflictsFail(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	client.workerMu.Lock()
	client.workerRunning = true
	client.workerMu.Unlock()
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	session := &clientSession{client: client, authenticated: authenticated, send: func(*runnerv1.RunnerMessage) error { return nil }, rootContext: context.Background()}
	cancellation := &runnerv1.CancelJob{Lease: proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), CancellationId: "cancellation-1", Reason: "requested", Deadline: timestamppb.New(now.Add(time.Minute)), Force: false}
	envelope := uniqueGatewayMessage(now, "cancel-command", &runnerv1.GatewayMessage_Cancel{Cancel: cancellation})
	if err := session.handleCancellation(envelope, now); err != nil {
		t.Fatal(err)
	}
	committed := client.journal.snapshot()
	if committed.Active == nil || len(committed.Active.CancellationDigest) != sha256.Size {
		t.Fatalf("committed cancellation = %#v", committed.Active)
	}
	reconnected := &clientSession{client: client, authenticated: authenticated, send: func(*runnerv1.RunnerMessage) error { return nil }, rootContext: context.Background()}
	replayed := uniqueGatewayMessage(now.Add(time.Second), "new-cancel-envelope", &runnerv1.GatewayMessage_Cancel{Cancel: proto.Clone(cancellation).(*runnerv1.CancelJob)})
	if err := reconnected.handleCancellation(replayed, now); err != nil {
		t.Fatalf("semantic reconnect replay with a fresh envelope rejected: %v", err)
	}
	for name, mutate := range map[string]func(*runnerv1.GatewayMessage){
		"reason": func(message *runnerv1.GatewayMessage) { message.GetCancel().Reason = "changed" },
		"deadline": func(message *runnerv1.GatewayMessage) {
			message.GetCancel().Deadline = timestamppb.New(now.Add(2 * time.Minute))
		},
		"force":           func(message *runnerv1.GatewayMessage) { message.GetCancel().Force = true },
		"cancellation id": func(message *runnerv1.GatewayMessage) { message.GetCancel().CancellationId = "cancellation-2" },
	} {
		t.Run(name, func(t *testing.T) {
			conflicting := proto.Clone(envelope).(*runnerv1.GatewayMessage)
			mutate(conflicting)
			if err := reconnected.handleCancellation(conflicting, now); err == nil || !strings.Contains(err.Error(), "conflicts") {
				t.Fatalf("conflicting cancellation error = %v", err)
			}
			after := client.journal.snapshot()
			if !bytes.Equal(after.Active.CancellationDigest, committed.Active.CancellationDigest) {
				t.Fatal("conflicting cancellation mutated committed identity")
			}
		})
	}
	client.markWorkerStopped()
}

func TestCancellationBeforeLeaseAcceptedAcknowledgementPreservesLeaseUntilCommand(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	client.worker = &gatedWorker{}
	client.config.Resources.CPUMillis = 2_000
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{
		client:        client,
		authenticated: authenticated,
		send: func(message *runnerv1.RunnerMessage) error {
			sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
			return nil
		},
		rootContext: context.Background(),
	}
	offerEnvelope := uniqueGatewayMessage(now, "offer", &runnerv1.GatewayMessage_Offer{Offer: validLeaseOffer(now)})
	if err := session.handleOffer(offerEnvelope, now); err != nil {
		t.Fatal(err)
	}
	accepted := sent[0]
	acknowledgement := eventAcknowledgement(now, "accepted-cancel-ack", accepted, runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED, runnerv1.JobPhase_JOB_PHASE_CANCELLING).GetEventAcknowledgement()
	acknowledgement.Reconciliation.Disposition = runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE
	acknowledgement.Reconciliation.CancellationId = "cancellation-1"
	if err := session.handleEventAcknowledgement(acknowledgement, now); err != nil {
		t.Fatal(err)
	}
	state := client.journal.snapshot()
	if state.Active == nil || state.Active.Phase != runnerv1.JobPhase_JOB_PHASE_CANCELLING || state.Active.CancellationID != "cancellation-1" || len(state.Active.CancellationDigest) != 0 || len(state.PendingMessage) != 0 {
		t.Fatalf("cancellation reconciliation state = %#v", state)
	}
	if len(sent) != 1 {
		t.Fatalf("preparation advanced before cancellation command: %#v", sent)
	}
	cancellation := &runnerv1.CancelJob{Lease: proto.Clone(offerEnvelope.GetOffer().GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offerEnvelope.GetOffer().GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), CancellationId: "cancellation-1", Reason: "requested", Deadline: timestamppb.New(now.Add(time.Minute))}
	if err := session.handleCancellation(uniqueGatewayMessage(now, "cancel-command", &runnerv1.GatewayMessage_Cancel{Cancel: cancellation}), now); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[1].GetCancelled() == nil || sent[1].GetCancelled().GetCancellationId() != "cancellation-1" {
		t.Fatalf("cancel command result = %#v", sent)
	}
}

func TestCancellationDuringTerminalResultDiscardsResultAndWaitsForCommand(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{client: client, authenticated: authenticatedMessage(now, platformScope()).GetAuthenticated(), send: func(message *runnerv1.RunnerMessage) error {
		sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}, rootContext: context.Background()}
	result := execution.Result{SchemaVersion: execution.ResultSchemaVersion, Status: "passed", Classification: execution.ClassificationPassed, Phase: execution.PhaseCompleted, StartedAt: now, CompletedAt: now}
	if err := session.queueResult(result); err != nil {
		t.Fatal(err)
	}
	completed := sent[0]
	acknowledgement := eventAcknowledgement(now, "completed-cancel-ack", completed, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_CANCELLING).GetEventAcknowledgement()
	acknowledgement.Reconciliation.Disposition = runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE
	acknowledgement.Reconciliation.CancellationId = "cancellation-1"
	if err := session.handleEventAcknowledgement(acknowledgement, now); err != nil {
		t.Fatal(err)
	}
	state := client.journal.snapshot()
	if state.Active == nil || state.Active.CancellationID != "cancellation-1" || len(state.PendingMessage) != 0 || len(sent) != 1 {
		t.Fatalf("terminal cancellation race state = %#v, sent = %#v", state, sent)
	}
	cancellation := &runnerv1.CancelJob{Lease: proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), CancellationId: "cancellation-1", Reason: "requested", Deadline: timestamppb.New(now.Add(time.Minute))}
	if err := session.handleCancellation(uniqueGatewayMessage(now, "cancel-command", &runnerv1.GatewayMessage_Cancel{Cancel: cancellation}), now); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[1].GetCancelled() == nil {
		t.Fatalf("cancel command did not replace terminal result: %#v", sent)
	}
}

func TestDeferredCleanupResultWaitsForSemanticCancellationCommand(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	client.workerMu.Lock()
	client.workerRunning = true
	client.workerMu.Unlock()
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{client: client, authenticated: authenticated, send: func(message *runnerv1.RunnerMessage) error {
		sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}, rootContext: context.Background()}
	if err := session.queueRenewal(now); err != nil {
		t.Fatal(err)
	}
	cleanupResult := execution.Result{SchemaVersion: execution.ResultSchemaVersion, Status: "failed", Classification: execution.ClassificationCancelled, Phase: execution.PhaseCleanup, StartedAt: now, CompletedAt: now, Cleanup: &execution.CleanupResult{Attempted: true, Succeeded: false, Error: "cleanup evidence unavailable"}}
	if err := session.handleWorkerEvent(workerEvent{result: &cleanupResult}); err != nil {
		t.Fatal(err)
	}
	if client.isWorkerRunning() || len(session.deferred) != 1 {
		t.Fatalf("deferred cleanup state: workerRunning=%t deferred=%d", client.isWorkerRunning(), len(session.deferred))
	}
	renewal := sent[0]
	acknowledgement := eventAcknowledgement(now, "renewal-cancel-ack", renewal, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_CANCELLING).GetEventAcknowledgement()
	acknowledgement.Reconciliation.Disposition = runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE
	acknowledgement.Reconciliation.CancellationId = "cancellation-1"
	if err := session.handleEventAcknowledgement(acknowledgement, now); err != nil {
		t.Fatal(err)
	}
	if state := client.journal.snapshot(); state.Active == nil || len(state.Active.CancellationDigest) != 0 || len(state.PendingMessage) != 0 || len(session.deferred) != 1 {
		t.Fatalf("pre-command cancellation state = %#v, deferred=%d", state, len(session.deferred))
	}
	cancellation := &runnerv1.CancelJob{Lease: proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), CancellationId: "cancellation-1", Reason: "requested", Deadline: timestamppb.New(now.Add(time.Minute))}
	if err := session.handleCancellation(uniqueGatewayMessage(now, "cancel-command", &runnerv1.GatewayMessage_Cancel{Cancel: cancellation}), now); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[1].GetCancelled() == nil || sent[1].GetCancelled().GetCleanupCompleted() || sent[1].GetCancelled().GetCleanupFailure().GetCode() != "cleanup_failed" || len(session.deferred) != 0 {
		t.Fatalf("cancellation cleanup result = %#v, deferred=%d", sent, len(session.deferred))
	}
}

func TestDuplicateSemanticAcknowledgementsAreIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	client.worker = &gatedWorker{}
	client.config.Resources.CPUMillis = 2_000
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{client: client, authenticated: authenticated, seen: make(map[string][sha256.Size]byte), send: func(message *runnerv1.RunnerMessage) error {
		sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}, rootContext: context.Background()}
	if err := session.sendHeartbeat(now); err != nil {
		t.Fatal(err)
	}
	heartbeatAck := &runnerv1.HeartbeatAcknowledgement{RunnerMessageId: sent[0].GetMessageId(), Sequence: sent[0].GetHeartbeat().GetSequence(), CommittedAt: timestamppb.New(now)}
	for _, gatewayID := range []string{"heartbeat-ack-1", "heartbeat-ack-2"} {
		envelope := uniqueGatewayMessage(now, gatewayID, &runnerv1.GatewayMessage_HeartbeatAcknowledgement{HeartbeatAcknowledgement: proto.Clone(heartbeatAck).(*runnerv1.HeartbeatAcknowledgement)})
		duplicate, err := session.gatewayMessageDuplicate(envelope)
		if err != nil || duplicate {
			t.Fatalf("gateway heartbeat acknowledgement %s duplicate = %t, %v", gatewayID, duplicate, err)
		}
		if err := session.handleGatewayMessage(envelope, now); err != nil {
			t.Fatalf("gateway heartbeat acknowledgement %s: %v", gatewayID, err)
		}
	}
	offerEnvelope := uniqueGatewayMessage(now, "offer", &runnerv1.GatewayMessage_Offer{Offer: validLeaseOffer(now)})
	if err := session.handleOffer(offerEnvelope, now); err != nil {
		t.Fatal(err)
	}
	accepted := sent[len(sent)-1]
	eventAck := eventAcknowledgement(now, "unused", accepted, runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED, runnerv1.JobPhase_JOB_PHASE_ACCEPTED).GetEventAcknowledgement()
	for _, gatewayID := range []string{"event-ack-1", "event-ack-2"} {
		payload := proto.Clone(eventAck).(*runnerv1.RunnerEventAcknowledgement)
		if gatewayID == "event-ack-2" {
			payload.Reconciliation.Disposition = runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_ALREADY_APPLIED
			payload.Reconciliation.Status = runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE
			payload.Reconciliation.Phase = runnerv1.JobPhase_JOB_PHASE_PREPARING
			payload.Reconciliation.Lease.ExpiresAt = timestamppb.New(now.Add(9 * time.Minute))
		}
		envelope := uniqueGatewayMessage(now, gatewayID, &runnerv1.GatewayMessage_EventAcknowledgement{EventAcknowledgement: payload})
		duplicate, err := session.gatewayMessageDuplicate(envelope)
		if err != nil || duplicate {
			t.Fatalf("gateway event acknowledgement %s duplicate = %t, %v", gatewayID, duplicate, err)
		}
		if err := session.handleGatewayMessage(envelope, now); err != nil {
			t.Fatalf("gateway event acknowledgement %s: %v", gatewayID, err)
		}
	}
	if pending := client.journal.snapshot().PendingMessage; len(pending) == 0 {
		t.Fatal("duplicate accepted acknowledgement removed the queued preparing event")
	}
	conflicting := proto.Clone(eventAck).(*runnerv1.RunnerEventAcknowledgement)
	conflicting.Reconciliation.Lease.LeaseId = "10000000-0000-0000-0000-000000000002"
	if err := session.handleEventAcknowledgement(conflicting, now); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("conflicting already-applied event acknowledgement error = %v", err)
	}
}

func TestLateHeartbeatAcknowledgementAllowsAlreadyAppliedStateAdvancement(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	session := &clientSession{client: client, authenticated: authenticatedMessage(now, platformScope()).GetAuthenticated(), send: func(*runnerv1.RunnerMessage) error { return nil }, rootContext: context.Background()}
	if err := session.sendHeartbeat(now); err != nil {
		t.Fatal(err)
	}
	heartbeat := session.pendingHeartbeat
	reconciliation := &runnerv1.LeaseReconciliation{Lease: proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, Status: runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED, Phase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED}
	first := &runnerv1.HeartbeatAcknowledgement{RunnerMessageId: heartbeat.GetMessageId(), Sequence: heartbeat.GetHeartbeat().GetSequence(), Reconciliations: []*runnerv1.LeaseReconciliation{reconciliation}, CommittedAt: timestamppb.New(now)}
	if err := session.handleHeartbeatAcknowledgement(first, now); err != nil {
		t.Fatal(err)
	}
	second := proto.Clone(first).(*runnerv1.HeartbeatAcknowledgement)
	second.Reconciliations[0].Disposition = runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_ALREADY_APPLIED
	second.Reconciliations[0].Status = runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE
	second.Reconciliations[0].Phase = runnerv1.JobPhase_JOB_PHASE_PREPARING
	second.Reconciliations[0].Lease.ExpiresAt = timestamppb.New(now.Add(9 * time.Minute))
	if err := session.handleHeartbeatAcknowledgement(second, now); err != nil {
		t.Fatal(err)
	}
	state := client.journal.snapshot()
	if state.Active == nil || state.Active.Phase != runnerv1.JobPhase_JOB_PHASE_PREPARING || !state.Active.ExpiresAt.Equal(now.Add(9*time.Minute)) {
		t.Fatalf("late heartbeat reconciliation state = %#v", state)
	}
	conflicting := proto.Clone(second).(*runnerv1.HeartbeatAcknowledgement)
	conflicting.Reconciliations[0].Attempt.AttemptId = "30000000-0000-0000-0000-000000000002"
	if err := session.handleHeartbeatAcknowledgement(conflicting, now); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("conflicting heartbeat acknowledgement error = %v", err)
	}
}

func TestHeartbeatTerminalReconciliationSettlesLateTerminalEventAcknowledgement(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := &runnerv1.RunnerMessage{MessageId: "000000000000000000000000-0000000000000001", SentAt: timestamppb.New(now), Payload: &runnerv1.RunnerMessage_Heartbeat{Heartbeat: &runnerv1.Heartbeat{Sequence: 1, Capacity: &runnerv1.Capacity{ConcurrentJobs: 1}, ActiveLeases: []*runnerv1.HeartbeatLease{{Lease: offer.GetJob().GetLease(), Attempt: offer.GetJob().GetAttempt(), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING}}, ObservedAt: timestamppb.New(now)}}}
	encodedHeartbeat, err := proto.MarshalOptions{Deterministic: true}.Marshal(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	terminal := &runnerv1.RunnerMessage{MessageId: "000000000000000000000000-0000000000000002", SentAt: timestamppb.New(now), Payload: &runnerv1.RunnerMessage_Completed{Completed: &runnerv1.JobCompleted{Lease: offer.GetJob().GetLease(), Attempt: offer.GetJob().GetAttempt(), Result: &runnerv1.StructuredResult{Outcome: runnerv1.ResultOutcome_RESULT_OUTCOME_PASSED, StartedAt: timestamppb.New(now), CompletedAt: timestamppb.New(now)}}}}
	pending, err := proto.MarshalOptions{Deterministic: true}.Marshal(terminal)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.MessageSequence = 2
		state.HeartbeatSequence = 1
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		state.PendingMessage = pending
		state.PendingHeartbeat = encodedHeartbeat
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	session := &clientSession{client: client, authenticated: authenticatedMessage(now, platformScope()).GetAuthenticated(), send: func(*runnerv1.RunnerMessage) error { return nil }, rootContext: context.Background()}
	if err := session.sendHeartbeat(now); err != nil {
		t.Fatal(err)
	}
	reconciliation := &runnerv1.LeaseReconciliation{Lease: proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, Status: runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, TerminalMessageId: terminal.GetMessageId()}
	heartbeatAck := &runnerv1.HeartbeatAcknowledgement{RunnerMessageId: heartbeat.GetMessageId(), Sequence: heartbeat.GetHeartbeat().GetSequence(), Reconciliations: []*runnerv1.LeaseReconciliation{reconciliation}, CommittedAt: timestamppb.New(now)}
	if err := session.handleHeartbeatAcknowledgement(heartbeatAck, now); err != nil {
		t.Fatal(err)
	}
	state := client.journal.snapshot()
	if state.Active != nil || len(state.PendingMessage) != 0 {
		t.Fatalf("terminal heartbeat reconciliation state = %#v", state)
	}
	late := eventAcknowledgement(now, "late-terminal-ack", terminal, runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED, runnerv1.JobPhase_JOB_PHASE_RUNNING).GetEventAcknowledgement()
	if err := session.handleEventAcknowledgement(late, now); err != nil {
		t.Fatalf("late terminal event acknowledgement was not idempotent: %v", err)
	}
}

func TestTerminalHeartbeatCleanupResultReleasesCapacityForNextOffer(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	client.worker = &gatedWorker{}
	client.config.Resources.CPUMillis = 2_000
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	client.workerMu.Lock()
	client.workerRunning = true
	client.workerMu.Unlock()
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{client: client, authenticated: authenticated, send: func(message *runnerv1.RunnerMessage) error {
		sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}, rootContext: context.Background()}
	if err := session.sendHeartbeat(now); err != nil {
		t.Fatal(err)
	}
	heartbeat := session.pendingHeartbeat
	reconciliation := &runnerv1.LeaseReconciliation{Lease: proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, Status: runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, TerminalMessageId: "terminal-message"}
	acknowledgement := &runnerv1.HeartbeatAcknowledgement{RunnerMessageId: heartbeat.GetMessageId(), Sequence: heartbeat.GetHeartbeat().GetSequence(), Reconciliations: []*runnerv1.LeaseReconciliation{reconciliation}, CommittedAt: timestamppb.New(now)}
	if err := session.handleHeartbeatAcknowledgement(acknowledgement, now); err != nil {
		t.Fatal(err)
	}
	if !client.isWorkerRunning() {
		t.Fatal("worker cleanup unexpectedly completed before its result arrived")
	}
	result := execution.Result{SchemaVersion: execution.ResultSchemaVersion, Status: "passed", Classification: execution.ClassificationPassed, Phase: execution.PhaseCompleted, StartedAt: now, CompletedAt: now}
	if err := session.handleWorkerEvent(workerEvent{result: &result}); err != nil {
		t.Fatal(err)
	}
	if client.isWorkerRunning() {
		t.Fatal("terminal cleanup result did not release worker capacity")
	}
	if err := session.handleOffer(uniqueGatewayMessage(now, "next-offer", &runnerv1.GatewayMessage_Offer{Offer: validLeaseOffer(now)}), now); err != nil {
		t.Fatal(err)
	}
	if sent[len(sent)-1].GetLeaseAccepted() == nil {
		t.Fatalf("next offer was not accepted after cleanup: %#v", sent[len(sent)-1])
	}
}

func TestRenewalAcknowledgementExtendsAuthoritativeLeaseAndExpiryFailsRetryably(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	offer.Job.Lease.ExpiresAt = timestamppb.New(now.Add(4 * time.Minute))
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{client: client, authenticated: authenticated, send: func(message *runnerv1.RunnerMessage) error {
		sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}, rootContext: context.Background()}
	if err := session.advance(now); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0].GetLeaseRenewal() == nil || sent[0].GetLeaseRenewal().GetRequestedExtension().AsDuration() != 10*time.Minute {
		t.Fatalf("renewal = %#v", sent)
	}
	renewedLease := proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity)
	renewedLease.ExpiresAt = timestamppb.New(now.Add(10 * time.Minute))
	reconciliation := &runnerv1.LeaseReconciliation{Lease: renewedLease, Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_ALREADY_APPLIED, Status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING}
	acknowledgement := &runnerv1.RunnerEventAcknowledgement{RunnerMessageId: sent[0].GetMessageId(), Reconciliation: reconciliation, CommittedAt: timestamppb.New(now)}
	if err := session.handleEventAcknowledgement(acknowledgement, now); err != nil {
		t.Fatal(err)
	}
	state := client.journal.snapshot()
	if state.Active == nil || !state.Active.ExpiresAt.Equal(now.Add(10*time.Minute)) || len(state.PendingMessage) != 0 {
		t.Fatalf("renewed state = %#v", state)
	}
	if err := client.journal.update(func(state *journalState) error {
		specification := new(runnerv1.JobSpecification)
		if err := proto.Unmarshal(state.Active.Specification, specification); err != nil {
			return err
		}
		specification.Lease.ExpiresAt = timestamppb.New(now)
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(specification)
		if err != nil {
			return err
		}
		state.Active.Specification = encoded
		state.Active.ExpiresAt = now
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := session.advance(now); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[1].GetFailed().GetFailure().GetCode() != "lease_expired" || !sent[1].GetFailed().GetFailure().GetRetryable() {
		t.Fatalf("expiry result = %#v", sent)
	}
}

func TestCancellationWaitsForCleanupAndEmitsJobCancelled(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	offer := validLeaseOffer(now)
	worker := &cancellingWorker{started: now}
	server := &testGateway{connect: func(stream grpc.BidiStreamingServer[runnerv1.RunnerMessage, runnerv1.GatewayMessage]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		authenticated := authenticatedMessage(now, platformScope())
		authenticated.GetAuthenticated().LeaseDuration = durationpb.New(10 * time.Minute)
		if err := stream.Send(authenticated); err != nil {
			return err
		}
		if _, err := stream.Recv(); err != nil {
			return err
		}
		heartbeat, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(uniqueGatewayMessage(now, "heartbeat-ack", &runnerv1.GatewayMessage_HeartbeatAcknowledgement{HeartbeatAcknowledgement: &runnerv1.HeartbeatAcknowledgement{RunnerMessageId: heartbeat.GetMessageId(), Sequence: heartbeat.GetHeartbeat().GetSequence(), CommittedAt: timestamppb.New(now)}})); err != nil {
			return err
		}
		if err := stream.Send(uniqueGatewayMessage(now, "offer", &runnerv1.GatewayMessage_Offer{Offer: offer})); err != nil {
			return err
		}
		accepted, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(eventAcknowledgement(now, "accepted-ack", accepted, runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED, runnerv1.JobPhase_JOB_PHASE_ACCEPTED)); err != nil {
			return err
		}
		preparing, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(eventAcknowledgement(now, "preparing-ack", preparing, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_PREPARING)); err != nil {
			return err
		}
		started, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(eventAcknowledgement(now, "started-ack", started, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_RUNNING)); err != nil {
			return err
		}
		cancellation := &runnerv1.CancelJob{Lease: proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity), CancellationId: "cancellation-1", Reason: "requested", Deadline: timestamppb.New(now.Add(time.Minute))}
		if err := stream.Send(uniqueGatewayMessage(now, "cancel", &runnerv1.GatewayMessage_Cancel{Cancel: cancellation})); err != nil {
			return err
		}
		cancelled, err := stream.Recv()
		if err != nil || cancelled.GetCancelled() == nil || cancelled.GetCancelled().GetCancellationId() != "cancellation-1" || !cancelled.GetCancelled().GetCleanupCompleted() {
			return fmt.Errorf("cancelled result = %#v, %v", cancelled, err)
		}
		if err := stream.Send(eventAcknowledgement(now, "cancelled-ack", cancelled, runnerv1.LeaseStatus_LEASE_STATUS_CANCELLED, runnerv1.JobPhase_JOB_PHASE_CANCELLING)); err != nil {
			return err
		}
		return stream.Send(uniqueGatewayMessage(now, "shutdown", &runnerv1.GatewayMessage_Shutdown{Shutdown: &runnerv1.ShutdownRunner{ShutdownId: "shutdown", Deadline: timestamppb.New(now.Add(time.Minute))}}))
	}}
	client, closeConnection := bufconnClient(t, server)
	defer closeConnection()
	client.worker = worker
	client.config.Resources.CPUMillis = 2_000
	client.now = func() time.Time { return now }
	if err := client.Run(context.Background()); !errors.Is(err, ErrServerShutdown) {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestFailureMappingIsDeterministic(t *testing.T) {
	tests := []struct {
		classification execution.Classification
		phase          execution.Phase
		category       runnerv1.FailureCategory
		stage          runnerv1.FailureStage
		retryable      bool
		code           string
	}{
		{execution.ClassificationInvalidJob, execution.PhaseValidation, runnerv1.FailureCategory_FAILURE_CATEGORY_POLICY, runnerv1.FailureStage_FAILURE_STAGE_LEASE, false, "stable_code"},
		{execution.ClassificationWorkloadFailure, execution.PhaseExecution, runnerv1.FailureCategory_FAILURE_CATEGORY_PLUGIN, runnerv1.FailureStage_FAILURE_STAGE_EXECUTION, false, "stable_code"},
		{execution.ClassificationInfrastructureFailure, execution.PhasePreparation, runnerv1.FailureCategory_FAILURE_CATEGORY_INFRASTRUCTURE, runnerv1.FailureStage_FAILURE_STAGE_PREPARATION, true, "stable_code"},
		{execution.ClassificationTimedOut, execution.PhaseExecution, runnerv1.FailureCategory_FAILURE_CATEGORY_INFRASTRUCTURE, runnerv1.FailureStage_FAILURE_STAGE_EXECUTION, false, "job_timed_out"},
	}
	for _, test := range tests {
		result := execution.Result{Classification: test.classification, Phase: test.phase, Failure: execution.NewFailure(test.classification, "stable_code", "stable summary")}
		first := resultFailure(result)
		second := resultFailure(result)
		if !proto.Equal(first, second) || first.GetCategory() != test.category || first.GetStage() != test.stage || first.GetRetryable() != test.retryable || first.GetCode() != test.code {
			t.Fatalf("mapping for %s/%s = %#v / %#v", test.classification, test.phase, first, second)
		}
	}
}

func TestRecoveredTerminalEventIsReplayedAndNeverExecutesAgain(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	worker := &gatedWorker{preparing: make(chan struct{}), executed: make(chan struct{}), now: now}
	client.worker = worker
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	terminal := &runnerv1.RunnerMessage{MessageId: "000000000000000000000000-0000000000000001", SentAt: timestamppb.New(now), Payload: &runnerv1.RunnerMessage_Completed{Completed: &runnerv1.JobCompleted{Lease: offer.GetJob().GetLease(), Attempt: offer.GetJob().GetAttempt(), Result: &runnerv1.StructuredResult{Outcome: runnerv1.ResultOutcome_RESULT_OUTCOME_PASSED, StartedAt: timestamppb.New(now), CompletedAt: timestamppb.New(now)}}}}
	pending, err := proto.MarshalOptions{Deterministic: true}.Marshal(terminal)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.MessageSequence = 1
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		state.PendingMessage = pending
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	client.recovering = true
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{client: client, authenticated: authenticatedMessage(now, platformScope()).GetAuthenticated(), send: func(message *runnerv1.RunnerMessage) error { sent = append(sent, message); return nil }, rootContext: context.Background()}
	if err := session.replayPending(); err != nil || len(sent) != 1 || sent[0].GetCompleted() == nil {
		t.Fatalf("terminal replay = %#v, %v", sent, err)
	}
	acknowledgement := eventAcknowledgement(now, "terminal-ack", terminal, runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED, runnerv1.JobPhase_JOB_PHASE_RUNNING).GetEventAcknowledgement()
	if err := session.handleEventAcknowledgement(acknowledgement, now); err != nil {
		t.Fatal(err)
	}
	select {
	case <-worker.preparing:
		t.Fatal("recovered terminal work executed again")
	default:
	}
	state := client.journal.snapshot()
	if state.Active != nil || len(state.PendingMessage) != 0 {
		t.Fatalf("terminal state was not cleared: %#v", state)
	}
}

func TestWorkloadFailureIsACompletedFailedResult(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{client: client, authenticated: authenticatedMessage(now, platformScope()).GetAuthenticated(), send: func(message *runnerv1.RunnerMessage) error {
		sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}}
	result := execution.Result{SchemaVersion: execution.ResultSchemaVersion, Status: "failed", Classification: execution.ClassificationWorkloadFailure, Phase: execution.PhaseCompleted, StartedAt: now, CompletedAt: now, Failure: execution.NewFailure(execution.ClassificationWorkloadFailure, "assertion_failed", "assertion failed")}
	if err := session.queueResult(result); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0].GetCompleted().GetResult().GetOutcome() != runnerv1.ResultOutcome_RESULT_OUTCOME_FAILED || sent[0].GetFailed() != nil {
		t.Fatalf("workload failure result = %#v", sent)
	}
}

func eventAcknowledgement(now time.Time, gatewayMessageID string, runnerMessage *runnerv1.RunnerMessage, status runnerv1.LeaseStatus, phase runnerv1.JobPhase) *runnerv1.GatewayMessage {
	lease, attempt := runnerMessageIdentity(runnerMessage)
	reconciliation := &runnerv1.LeaseReconciliation{Lease: proto.Clone(lease).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(attempt).(*runnerv1.AttemptIdentity), Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, Status: status, Phase: phase}
	if terminalLeaseStatus(status) {
		reconciliation.TerminalMessageId = runnerMessage.GetMessageId()
	}
	return uniqueGatewayMessage(now, gatewayMessageID, &runnerv1.GatewayMessage_EventAcknowledgement{EventAcknowledgement: &runnerv1.RunnerEventAcknowledgement{RunnerMessageId: runnerMessage.GetMessageId(), Reconciliation: reconciliation, CommittedAt: timestamppb.New(now)}})
}

func uniqueGatewayMessage(now time.Time, id string, payload any) *runnerv1.GatewayMessage {
	message := gatewayMessage(now, payload)
	message.MessageId = id
	return message
}
