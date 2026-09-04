package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maximumRememberedGatewayMessageIDs = 4096

type clientSession struct {
	client                        *Client
	authenticated                 *runnerv1.Authenticated
	send                          func(*runnerv1.RunnerMessage) error
	jobCorrelationV1              bool
	seen                          map[string][sha256.Size]byte
	seenOrder                     []string
	pendingHeartbeat              *runnerv1.RunnerMessage
	rootContext                   context.Context
	cancelSession                 context.CancelFunc
	reconciled                    bool
	settledEvents                 map[string]settledRunnerEvent
	settledEventOrder             []string
	acknowledgedHeartbeats        map[string]*runnerv1.RunnerMessage
	acknowledgedHBOrder           []string
	heartbeatDeferred             bool
	generation                    uint64
	cancellationFinalUsageLease   *runnerv1.LeaseIdentity
	cancellationFinalUsageAttempt *runnerv1.AttemptIdentity
}

type settledRunnerEvent struct {
	message *runnerv1.RunnerMessage
	phase   runnerv1.JobPhase
}

func (s *clientSession) rememberGatewayMessage(message *runnerv1.GatewayMessage) error {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return permanent("encode gateway message: %v", err)
	}
	s.seen[message.GetMessageId()] = sha256.Sum256(data)
	s.seenOrder = append(s.seenOrder, message.GetMessageId())
	return nil
}

func (s *clientSession) gatewayMessageDuplicate(message *runnerv1.GatewayMessage) (bool, error) {
	if err := validateGatewayEnvelope(message, s.client.now().UTC()); err != nil {
		return false, err
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return false, permanent("encode gateway message: %v", err)
	}
	digest := sha256.Sum256(data)
	previous, exists := s.seen[message.GetMessageId()]
	if exists {
		if previous != digest {
			return false, permanent("gateway messageId was reused with another payload")
		}
		return true, nil
	}
	s.seen[message.GetMessageId()] = digest
	s.seenOrder = append(s.seenOrder, message.GetMessageId())
	if len(s.seenOrder) > maximumRememberedGatewayMessageIDs {
		delete(s.seen, s.seenOrder[0])
		s.seenOrder = s.seenOrder[1:]
	}
	return false, nil
}

func (s *clientSession) handleGatewayMessage(message *runnerv1.GatewayMessage, now time.Time) error {
	switch {
	case message.GetOffer() != nil:
		return s.handleOffer(message, now)
	case message.GetCancel() != nil:
		return s.handleCancellation(message, now)
	case message.GetEventAcknowledgement() != nil:
		return s.handleEventAcknowledgement(message.GetEventAcknowledgement(), now)
	case message.GetHeartbeatAcknowledgement() != nil:
		return s.handleHeartbeatAcknowledgement(message.GetHeartbeatAcknowledgement(), now)
	case message.GetDrain() != nil:
		drain := message.GetDrain()
		if err := validateIdentifier("drain.drainId", drain.GetDrainId(), maximumIdentifierBytes); err != nil {
			return permanent("%v", err)
		}
		if len(drain.GetReason()) > maximumReasonBytes || validateTimestamp("drain.deadline", drain.GetDeadline()) != nil {
			return permanent("drain is invalid")
		}
		s.client.Drain()
		return s.sendHeartbeat(now)
	case message.GetShutdown() != nil:
		shutdown := message.GetShutdown()
		if err := validateIdentifier("shutdown.shutdownId", shutdown.GetShutdownId(), maximumIdentifierBytes); err != nil {
			return permanent("%v", err)
		}
		if len(shutdown.GetReason()) > maximumReasonBytes || validateTimestamp("shutdown.deadline", shutdown.GetDeadline()) != nil {
			return permanent("shutdown is invalid")
		}
		return permanent("%w", ErrServerShutdown)
	case message.GetAuthenticated() != nil:
		return permanent("authenticated may only be sent as the first gateway message")
	case message.GetPolicyUpdate() != nil:
		return permanent("policy updates are not supported by this runner alpha")
	case message.GetCredentialRotation() != nil:
		return s.handleCredentialRotation(message.GetCredentialRotation(), now)
	default:
		return permanent("gateway message payload is missing or unsupported")
	}
}

func (s *clientSession) handleOffer(envelope *runnerv1.GatewayMessage, now time.Time) error {
	offer := envelope.GetOffer()
	encodedEnvelope, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		return err
	}
	offerDigest := sha256.Sum256(encodedEnvelope)
	state := s.client.journal.snapshot()
	if state.Active != nil || s.client.isWorkerRunning() {
		if state.Active == nil {
			return s.rejectOffer(offer, runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_AT_CAPACITY, "at_capacity: prior lease cleanup is still running")
		}
		if activeMatchesIdentity(state.Active, offer.GetJob().GetLease(), offer.GetJob().GetAttempt()) {
			persisted := new(runnerv1.JobSpecification)
			if err := proto.Unmarshal(state.Active.Specification, persisted); err != nil {
				return permanent("decode active job specification: %v", err)
			}
			if !proto.Equal(persisted.GetJobCorrelation(), offer.GetJob().GetJobCorrelation()) {
				return permanent("job correlation changed for an active durable job identity")
			}
		}
		if state.Active.OfferMessageID == envelope.GetMessageId() && bytes.Equal(state.Active.OfferDigest, offerDigest[:]) {
			return s.replayPending()
		}
		return s.rejectOffer(offer, runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_AT_CAPACITY, "at_capacity: runner already has an active lease")
	}
	if len(state.PendingMessage) != 0 {
		return permanent("runner has an unacknowledged lease rejection")
	}
	if s.client.draining.Load() {
		return s.rejectOffer(offer, runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_DRAINING, "draining: runner is draining")
	}
	if s.client.worker == nil {
		return s.rejectOffer(offer, runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED, "worker_unavailable: remote execution is unavailable")
	}
	if rejection := s.client.validateOffer(offer, now, s.authenticated.GetLeaseDuration().AsDuration(), s.jobCorrelationV1); rejection != nil {
		return s.rejectOffer(offer, rejection.Reason, rejection.Code+": "+rejection.Message)
	}
	target, rejection := validateCompleteLogUpload(offer.GetJob().GetCompleteLogUpload(), now, offer.GetOfferExpiresAt().AsTime(), offer.GetJob().GetLease().GetExpiresAt().AsTime())
	if rejection != nil {
		return s.rejectOffer(offer, rejection.Reason, rejection.Code+": "+rejection.Message)
	}
	sanitizedJob := proto.Clone(offer.GetJob()).(*runnerv1.JobSpecification)
	sanitizedJob.CompleteLogUpload = nil
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(sanitizedJob)
	if err != nil {
		return err
	}
	if err := s.client.beginRestartEvidence(offer.GetJob().GetLease(), offer.GetJob().GetAttempt()); err != nil {
		return permanent("initialize restart evidence: %v", err)
	}
	accepted := &runnerv1.LeaseAccepted{
		Lease:      proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity),
		Attempt:    proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity),
		AcceptedAt: timestamppb.New(now),
	}
	err = s.queueDurable(&runnerv1.RunnerMessage_LeaseAccepted{LeaseAccepted: accepted}, func(state *journalState) error {
		if state.Active != nil || len(state.PendingMessage) != 0 {
			return errors.New("runner became busy while accepting the lease")
		}
		state.Active = &journalJob{
			Specification:    specification,
			OfferMessageID:   envelope.GetMessageId(),
			OfferDigest:      bytes.Clone(offerDigest[:]),
			JobCorrelationV1: s.jobCorrelationV1,
			Phase:            runnerv1.JobPhase_JOB_PHASE_ACCEPTED,
			ExpiresAt:        offer.GetJob().GetLease().GetExpiresAt().AsTime(),
		}
		return nil
	})
	acceptedState := s.client.journal.snapshot()
	if err != nil && acceptedState.Active == nil {
		return errors.Join(err, s.client.clearRestartEvidence())
	}
	if acceptedState.Active != nil && activeMatchesIdentity(acceptedState.Active, offer.GetJob().GetLease(), offer.GetJob().GetAttempt()) {
		s.client.setCompleteLogTarget(offer.GetJob(), target)
	} else {
		s.client.clearCompleteLogTarget()
	}
	return err
}

func (s *clientSession) rejectOffer(offer *runnerv1.LeaseOffer, reason runnerv1.LeaseRejectionReason, summary string) error {
	if offer == nil || offer.GetJob() == nil || offer.GetJob().GetLease() == nil || offer.GetJob().GetAttempt() == nil {
		return permanent("cannot durably reject a lease offer without lease and attempt identity")
	}
	summary = boundedSummary(summary)
	rejection := &runnerv1.LeaseRejected{
		Lease:   proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity),
		Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity),
		Reason:  reason,
		Summary: summary,
	}
	return s.queueDurable(&runnerv1.RunnerMessage_LeaseRejected{LeaseRejected: rejection}, nil)
}

func (s *clientSession) queueDurable(payload any, mutate func(*journalState) error) error {
	message, err := s.client.runnerMessage()
	if err != nil {
		return err
	}
	switch payload := payload.(type) {
	case *runnerv1.RunnerMessage_LeaseAccepted:
		message.Payload = payload
	case *runnerv1.RunnerMessage_LeaseRejected:
		message.Payload = payload
	case *runnerv1.RunnerMessage_LeaseRenewal:
		message.Payload = payload
	case *runnerv1.RunnerMessage_JobPreparing:
		message.Payload = payload
	case *runnerv1.RunnerMessage_JobStarted:
		message.Payload = payload
	case *runnerv1.RunnerMessage_Completed:
		message.Payload = payload
	case *runnerv1.RunnerMessage_Failed:
		message.Payload = payload
	case *runnerv1.RunnerMessage_Cancelled:
		message.Payload = payload
	default:
		return errors.New("unsupported durable runner event")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return err
	}
	if err := s.client.journal.update(func(state *journalState) error {
		if len(state.PendingMessage) != 0 {
			return errors.New("runner already has an unacknowledged durable event")
		}
		if mutate != nil {
			if err := mutate(state); err != nil {
				return err
			}
		}
		state.PendingMessage = encoded
		return nil
	}); err != nil {
		return err
	}
	return s.send(message)
}

func (s *clientSession) replayPending() error {
	pending := s.client.journal.snapshot().PendingMessage
	if len(pending) == 0 {
		return nil
	}
	message := new(runnerv1.RunnerMessage)
	if err := proto.Unmarshal(pending, message); err != nil {
		return err
	}
	return s.send(message)
}

func (s *clientSession) handleEventAcknowledgement(acknowledgement *runnerv1.RunnerEventAcknowledgement, now time.Time) error {
	if acknowledgement == nil || validateTimestamp("eventAcknowledgement.committedAt", acknowledgement.GetCommittedAt()) != nil {
		return permanent("event acknowledgement is invalid")
	}
	if settled, exists := s.settledEvents[acknowledgement.GetRunnerMessageId()]; exists {
		return s.handleSettledEventAcknowledgement(settled, acknowledgement, now)
	}
	state := s.client.journal.snapshot()
	if len(state.PendingMessage) == 0 {
		return permanent("event acknowledgement has no pending runner event")
	}
	pending := new(runnerv1.RunnerMessage)
	if err := proto.Unmarshal(state.PendingMessage, pending); err != nil {
		return permanent("decode pending runner event: %v", err)
	}
	if acknowledgement.GetRunnerMessageId() != pending.GetMessageId() {
		return permanent("event acknowledgement does not match the pending runner message")
	}
	reconciliation := acknowledgement.GetReconciliation()
	if err := validateReconciliation(reconciliation); err != nil {
		return permanent("event acknowledgement: %v", err)
	}
	pendingLease, pendingAttempt := runnerMessageIdentity(pending)
	if pendingLease == nil || pendingAttempt == nil || !sameLeaseAttempt(pendingLease, pendingAttempt, reconciliation.GetLease(), reconciliation.GetAttempt()) {
		return permanent("event acknowledgement reconciliation identity does not match the pending event")
	}
	activeMatches := state.Active != nil && activeMatchesIdentity(state.Active, reconciliation.GetLease(), reconciliation.GetAttempt())
	if err := validatePendingReconciliation(pending, reconciliation, state); err != nil {
		return permanent("event acknowledgement: %v", err)
	}
	terminal := terminalLeaseStatus(reconciliation.GetStatus())
	cancelling := !terminal && reconciliation.GetCancellationId() != ""
	if cancelling {
		if activeMatches {
			if err := s.applyAuthoritativeReconciliation(reconciliation); err != nil {
				return err
			}
			s.client.stopWorker(context.Canceled)
			s.client.failStartResponse(context.Canceled)
		}
		if err := s.clearPendingAcknowledged(pending, state.Active); err != nil {
			return err
		}
		if activeMatches {
			return s.advance(now)
		}
		return nil
	}
	if terminal && activeMatches {
		s.client.stopWorker(errors.New("gateway reconciled the lease as terminal"))
		s.client.failStartResponse(errors.New("gateway reconciled the lease as terminal"))
		err := s.client.journal.update(func(state *journalState) error {
			state.Active = nil
			state.PendingMessage = nil
			return nil
		})
		if err == nil {
			s.client.clearCompleteLogTarget()
			s.client.recovering = false
			s.rememberSettledMessage(pending, state.Active.Phase)
			s.discardDeferred(errors.New("gateway reconciled the lease as terminal"))
			err = s.client.clearRestartEvidence()
		}
		return err
	}
	if activeMatches {
		if err := s.applyAuthoritativeReconciliation(reconciliation); err != nil {
			return err
		}
	}
	if reconciliation.GetDisposition() == runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE {
		if err := s.clearPendingAcknowledged(pending, state.Active); err != nil {
			return err
		}
		return s.reissueStaleEvent(pending, now)
	}
	if pending.GetLeaseRejected() != nil {
		return s.clearPendingAcknowledged(pending, state.Active)
	}
	if terminal {
		return s.clearPendingAcknowledged(pending, state.Active)
	}
	switch {
	case pending.GetLeaseAccepted() != nil:
		if err := s.clearPendingAcknowledged(pending, state.Active); err != nil {
			return err
		}
		if s.client.recovering {
			return s.queueRestartFailure(now)
		}
		if s.client.journal.snapshot().Active.CancellationID != "" {
			return s.advance(now)
		}
		return s.queuePreparing(now)
	case pending.GetJobPreparing() != nil:
		if err := s.clearPendingAcknowledged(pending, state.Active); err != nil {
			return err
		}
		if s.client.recovering {
			return s.queueRestartFailure(now)
		}
		if s.client.journal.snapshot().Active.CancellationID != "" {
			return s.advance(now)
		}
		return s.client.startWorker(s.rootContext)
	case pending.GetJobStarted() != nil:
		if err := s.clearPendingAcknowledged(pending, state.Active); err != nil {
			return err
		}
		if s.client.recovering {
			return s.queueRestartFailure(now)
		}
		s.client.completeStartResponse(nil)
		return s.drainDeferred(now)
	case pending.GetLeaseRenewal() != nil:
		if err := s.clearPendingAcknowledged(pending, state.Active); err != nil {
			return err
		}
		if s.client.recovering {
			return s.queueRestartFailure(now)
		}
		return s.drainDeferred(now)
	case pending.GetCompleted() != nil, pending.GetFailed() != nil, pending.GetCancelled() != nil:
		s.client.recovering = false
		s.client.stopWorker(nil)
		s.client.failStartResponse(errors.New("job reached a terminal state"))
		err := s.client.journal.update(func(state *journalState) error {
			state.Active = nil
			state.PendingMessage = nil
			return nil
		})
		if err == nil {
			s.client.clearCompleteLogTarget()
			s.rememberSettledMessage(pending, state.Active.Phase)
			s.discardDeferred(errors.New("job reached a terminal state"))
			err = s.client.clearRestartEvidence()
		}
		return err
	default:
		return permanent("pending runner event is unsupported")
	}
}

func (s *clientSession) reissueStaleEvent(message *runnerv1.RunnerMessage, now time.Time) error {
	lease, attempt := runnerMessageIdentity(message)
	state := s.client.journal.snapshot()
	if state.Active != nil && activeMatchesIdentity(state.Active, lease, attempt) {
		var err error
		lease, attempt, err = activeIdentity(state)
		if err != nil {
			return err
		}
	} else {
		lease = proto.Clone(lease).(*runnerv1.LeaseIdentity)
		attempt = proto.Clone(attempt).(*runnerv1.AttemptIdentity)
	}
	switch {
	case message.GetLeaseAccepted() != nil:
		accepted := proto.Clone(message.GetLeaseAccepted()).(*runnerv1.LeaseAccepted)
		accepted.Lease, accepted.Attempt, accepted.AcceptedAt = lease, attempt, timestamppb.New(now)
		return s.queueDurable(&runnerv1.RunnerMessage_LeaseAccepted{LeaseAccepted: accepted}, nil)
	case message.GetLeaseRejected() != nil:
		rejected := proto.Clone(message.GetLeaseRejected()).(*runnerv1.LeaseRejected)
		rejected.Lease, rejected.Attempt = lease, attempt
		return s.queueDurable(&runnerv1.RunnerMessage_LeaseRejected{LeaseRejected: rejected}, nil)
	case message.GetLeaseRenewal() != nil:
		renewal := proto.Clone(message.GetLeaseRenewal()).(*runnerv1.LeaseRenewal)
		renewal.Lease, renewal.Attempt, renewal.ObservedAt = lease, attempt, timestamppb.New(now)
		return s.queueDurable(&runnerv1.RunnerMessage_LeaseRenewal{LeaseRenewal: renewal}, nil)
	case message.GetJobPreparing() != nil:
		preparing := proto.Clone(message.GetJobPreparing()).(*runnerv1.JobPreparing)
		preparing.Lease, preparing.Attempt, preparing.StartedAt = lease, attempt, timestamppb.New(now)
		return s.queueDurable(&runnerv1.RunnerMessage_JobPreparing{JobPreparing: preparing}, nil)
	case message.GetJobStarted() != nil:
		started := proto.Clone(message.GetJobStarted()).(*runnerv1.JobStarted)
		started.Lease, started.Attempt, started.StartedAt = lease, attempt, timestamppb.New(now)
		return s.queueDurable(&runnerv1.RunnerMessage_JobStarted{JobStarted: started}, nil)
	case message.GetCompleted() != nil:
		completed := proto.Clone(message.GetCompleted()).(*runnerv1.JobCompleted)
		completed.Lease, completed.Attempt = lease, attempt
		return s.queueDurable(&runnerv1.RunnerMessage_Completed{Completed: completed}, nil)
	case message.GetFailed() != nil:
		failed := proto.Clone(message.GetFailed()).(*runnerv1.JobFailed)
		failed.Lease, failed.Attempt = lease, attempt
		return s.queueDurable(&runnerv1.RunnerMessage_Failed{Failed: failed}, nil)
	case message.GetCancelled() != nil:
		cancelled := proto.Clone(message.GetCancelled()).(*runnerv1.JobCancelled)
		cancelled.Lease, cancelled.Attempt = lease, attempt
		return s.queueDurable(&runnerv1.RunnerMessage_Cancelled{Cancelled: cancelled}, nil)
	default:
		return errors.New("stale runner event cannot be reissued")
	}
}

func (s *clientSession) clearPendingAcknowledged(pending *runnerv1.RunnerMessage, active *journalJob) error {
	if err := s.clearPending(); err != nil {
		return err
	}
	phase := runnerv1.JobPhase_JOB_PHASE_UNSPECIFIED
	if active != nil {
		phase = active.Phase
	}
	s.rememberSettledMessage(pending, phase)
	return nil
}

func validateSettledEventAcknowledgement(settled settledRunnerEvent, acknowledgement *runnerv1.RunnerEventAcknowledgement) error {
	reconciliation := acknowledgement.GetReconciliation()
	if err := validateReconciliation(reconciliation); err != nil {
		return err
	}
	lease, attempt := runnerMessageIdentity(settled.message)
	if lease == nil || attempt == nil || !sameLeaseAttempt(lease, attempt, reconciliation.GetLease(), reconciliation.GetAttempt()) {
		return errors.New("reconciliation identity does not match the settled event")
	}
	if reconciliation.GetDisposition() == runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE || terminalLeaseStatus(reconciliation.GetStatus()) {
		return nil
	}
	status := reconciliation.GetStatus()
	phase := reconciliation.GetPhase()
	minimumPhase := settled.phase
	switch {
	case settled.message.GetLeaseRejected() != nil, settled.message.GetCompleted() != nil, settled.message.GetFailed() != nil, settled.message.GetCancelled() != nil:
		return errors.New("terminal or rejected event reconciliation must be stale or terminal")
	case settled.message.GetLeaseAccepted() != nil:
		minimumPhase = runnerv1.JobPhase_JOB_PHASE_ACCEPTED
		if status != runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED && status != runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE {
			return errors.New("accepted event reconciliation status is invalid")
		}
	case settled.message.GetJobPreparing() != nil:
		minimumPhase = runnerv1.JobPhase_JOB_PHASE_PREPARING
		if status != runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE {
			return errors.New("preparing event reconciliation status is invalid")
		}
	case settled.message.GetJobStarted() != nil:
		minimumPhase = runnerv1.JobPhase_JOB_PHASE_RUNNING
		if status != runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE {
			return errors.New("started event reconciliation status is invalid")
		}
	case settled.message.GetLeaseRenewal() != nil:
		if status != runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE {
			return errors.New("renewal event reconciliation status is invalid")
		}
	default:
		return errors.New("settled runner event is unsupported")
	}
	if jobPhaseRank(phase) < jobPhaseRank(minimumPhase) {
		return errors.New("reconciliation regressed behind the settled event")
	}
	return nil
}

func (s *clientSession) handleSettledEventAcknowledgement(settled settledRunnerEvent, acknowledgement *runnerv1.RunnerEventAcknowledgement, now time.Time) error {
	if err := validateSettledEventAcknowledgement(settled, acknowledgement); err != nil {
		return permanent("event acknowledgement conflicts with authoritative reconciliation: %v", err)
	}
	if err := s.applyLateReconciliation(acknowledgement.GetReconciliation(), now); err != nil {
		return err
	}
	return s.advance(now)
}

func (s *clientSession) applyLateReconciliation(reconciliation *runnerv1.LeaseReconciliation, now time.Time) error {
	state := s.client.journal.snapshot()
	if state.Active == nil || !activeMatchesIdentity(state.Active, reconciliation.GetLease(), reconciliation.GetAttempt()) {
		return nil
	}
	terminal := terminalLeaseStatus(reconciliation.GetStatus())
	if terminal {
		s.client.stopWorker(errors.New("gateway reconciled the lease as terminal"))
		s.client.failStartResponse(errors.New("gateway reconciled the lease as terminal"))
		pending := bytes.Clone(state.PendingMessage)
		if err := s.client.journal.update(func(state *journalState) error {
			state.Active = nil
			state.PendingMessage = nil
			return nil
		}); err != nil {
			return err
		}
		s.client.recovering = false
		s.client.clearCompleteLogTarget()
		s.rememberSettledEvent(pending, state.Active.Phase)
		s.discardDeferred(errors.New("gateway reconciled the lease as terminal"))
		return s.client.clearRestartEvidence()
	}
	if reconciliation.GetCancellationId() != "" {
		if err := s.applyAuthoritativeReconciliation(reconciliation); err != nil {
			return err
		}
		s.client.stopWorker(context.Canceled)
		s.client.failStartResponse(context.Canceled)
		return nil
	}
	if err := s.applyAuthoritativeReconciliation(reconciliation); err != nil {
		return err
	}
	return nil
}

func (s *clientSession) applyAuthoritativeReconciliation(reconciliation *runnerv1.LeaseReconciliation) error {
	return s.client.journal.update(func(state *journalState) error {
		if state.Active == nil || !activeMatchesIdentity(state.Active, reconciliation.GetLease(), reconciliation.GetAttempt()) {
			return errors.New("active lease changed during reconciliation")
		}
		specification := new(runnerv1.JobSpecification)
		if err := proto.Unmarshal(state.Active.Specification, specification); err != nil {
			return err
		}
		authoritativeLease := proto.Clone(reconciliation.GetLease()).(*runnerv1.LeaseIdentity)
		expiresAt := authoritativeLease.GetExpiresAt().AsTime()
		if expiresAt.Before(state.Active.ExpiresAt) {
			expiresAt = state.Active.ExpiresAt
			authoritativeLease.ExpiresAt = timestamppb.New(expiresAt)
		}
		specification.Lease = authoritativeLease
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(specification)
		if err != nil {
			return err
		}
		state.Active.Specification = encoded
		state.Active.ExpiresAt = expiresAt
		if reconciliation.GetPhase() != runnerv1.JobPhase_JOB_PHASE_UNSPECIFIED && jobPhaseRank(reconciliation.GetPhase()) >= jobPhaseRank(state.Active.Phase) {
			state.Active.Phase = reconciliation.GetPhase()
		}
		if reconciliation.GetCancellationId() != "" {
			if state.Active.CancellationID != "" && state.Active.CancellationID != reconciliation.GetCancellationId() {
				return errors.New("authoritative reconciliation changed the cancellation ID")
			}
			state.Active.CancellationID = reconciliation.GetCancellationId()
			state.Active.Phase = runnerv1.JobPhase_JOB_PHASE_CANCELLING
		}
		return nil
	})
}

func (s *clientSession) handleHeartbeatAcknowledgement(acknowledgement *runnerv1.HeartbeatAcknowledgement, now time.Time) error {
	if acknowledgement == nil || validateTimestamp("heartbeatAcknowledgement.committedAt", acknowledgement.GetCommittedAt()) != nil {
		return permanent("heartbeat acknowledgement is invalid")
	}
	current := s.pendingHeartbeat != nil && acknowledgement.GetRunnerMessageId() == s.pendingHeartbeat.GetMessageId()
	message := s.pendingHeartbeat
	if !current {
		message = s.acknowledgedHeartbeats[acknowledgement.GetRunnerMessageId()]
	}
	if message == nil {
		return permanent("heartbeat acknowledgement has no matching pending or applied heartbeat")
	}
	heartbeat := message.GetHeartbeat()
	if acknowledgement.GetSequence() != heartbeat.GetSequence() {
		return permanent("heartbeat acknowledgement does not match the pending heartbeat")
	}
	if len(acknowledgement.GetReconciliations()) != len(heartbeat.GetActiveLeases()) {
		return permanent("heartbeat acknowledgement reconciliation cardinality does not match active leases")
	}
	for index, reconciliation := range acknowledgement.GetReconciliations() {
		if err := validateReconciliation(reconciliation); err != nil {
			return permanent("heartbeat acknowledgement: %v", err)
		}
		expected := heartbeat.GetActiveLeases()[index]
		if !sameLeaseAttempt(expected.GetLease(), expected.GetAttempt(), reconciliation.GetLease(), reconciliation.GetAttempt()) {
			return permanent("heartbeat acknowledgement reconciliation identity does not match active lease")
		}
		if err := s.applyLateReconciliation(reconciliation, now); err != nil {
			return err
		}
	}
	if current {
		if err := s.client.journal.update(func(state *journalState) error {
			state.PendingHeartbeat = nil
			return nil
		}); err != nil {
			return err
		}
		s.pendingHeartbeat = nil
		s.heartbeatDeferred = false
		s.rememberAcknowledgedHeartbeat(message)
	}
	s.reconciled = true
	return s.advance(now)
}

func (s *clientSession) rememberSettledEvent(encoded []byte, phase runnerv1.JobPhase) {
	if len(encoded) == 0 {
		return
	}
	message := new(runnerv1.RunnerMessage)
	if proto.Unmarshal(encoded, message) != nil {
		return
	}
	s.rememberSettledMessage(message, phase)
}

func (s *clientSession) rememberSettledMessage(message *runnerv1.RunnerMessage, phase runnerv1.JobPhase) {
	if message == nil || message.GetMessageId() == "" {
		return
	}
	if s.settledEvents == nil {
		s.settledEvents = make(map[string]settledRunnerEvent)
	}
	if _, exists := s.settledEvents[message.GetMessageId()]; !exists {
		s.settledEventOrder = append(s.settledEventOrder, message.GetMessageId())
	}
	s.settledEvents[message.GetMessageId()] = settledRunnerEvent{message: proto.Clone(message).(*runnerv1.RunnerMessage), phase: phase}
	if len(s.settledEventOrder) > maximumRememberedGatewayMessageIDs {
		delete(s.settledEvents, s.settledEventOrder[0])
		s.settledEventOrder = s.settledEventOrder[1:]
	}
}

func (s *clientSession) rememberAcknowledgedHeartbeat(message *runnerv1.RunnerMessage) {
	if s.acknowledgedHeartbeats == nil {
		s.acknowledgedHeartbeats = make(map[string]*runnerv1.RunnerMessage)
	}
	if _, exists := s.acknowledgedHeartbeats[message.GetMessageId()]; !exists {
		s.acknowledgedHBOrder = append(s.acknowledgedHBOrder, message.GetMessageId())
	}
	s.acknowledgedHeartbeats[message.GetMessageId()] = proto.Clone(message).(*runnerv1.RunnerMessage)
	if len(s.acknowledgedHBOrder) > maximumRememberedGatewayMessageIDs {
		delete(s.acknowledgedHeartbeats, s.acknowledgedHBOrder[0])
		s.acknowledgedHBOrder = s.acknowledgedHBOrder[1:]
	}
}

func validateReconciliation(reconciliation *runnerv1.LeaseReconciliation) error {
	if reconciliation == nil || reconciliation.GetLease() == nil || reconciliation.GetAttempt() == nil {
		return errors.New("reconciliation identity is required")
	}
	if reconciliation.GetDisposition() != runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED && reconciliation.GetDisposition() != runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_ALREADY_APPLIED && reconciliation.GetDisposition() != runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE {
		return errors.New("reconciliation disposition is invalid")
	}
	switch reconciliation.GetStatus() {
	case runnerv1.LeaseStatus_LEASE_STATUS_OFFERED, runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED, runnerv1.LeaseStatus_LEASE_STATUS_CANCELLED, runnerv1.LeaseStatus_LEASE_STATUS_EXPIRED, runnerv1.LeaseStatus_LEASE_STATUS_RELEASED:
	default:
		return errors.New("reconciliation lease status is invalid")
	}
	switch reconciliation.GetPhase() {
	case runnerv1.JobPhase_JOB_PHASE_UNSPECIFIED, runnerv1.JobPhase_JOB_PHASE_ACCEPTED, runnerv1.JobPhase_JOB_PHASE_PREPARING, runnerv1.JobPhase_JOB_PHASE_RUNNING, runnerv1.JobPhase_JOB_PHASE_CANCELLING:
	default:
		return errors.New("reconciliation job phase is invalid")
	}
	if validateTimestamp("reconciliation.lease.expiresAt", reconciliation.GetLease().GetExpiresAt()) != nil {
		return errors.New("reconciliation lease status or expiry is invalid")
	}
	for field, value := range map[string]string{
		"leaseId": reconciliation.GetLease().GetLeaseId(), "jobId": reconciliation.GetLease().GetJobId(), "executionId": reconciliation.GetLease().GetExecutionId(),
		"attemptId": reconciliation.GetAttempt().GetAttemptId(), "releaseCandidateId": reconciliation.GetAttempt().GetReleaseCandidateId(), "matrixEntryId": reconciliation.GetAttempt().GetMatrixEntryId(),
	} {
		if err := validateUUID(field, value); err != nil {
			return err
		}
	}
	if reconciliation.GetAttempt().GetAttemptNumber() == 0 || reconciliation.GetAttempt().GetAttemptNumber() > maximumAttemptNumber {
		return errors.New("reconciliation attempt number is invalid")
	}
	for field, value := range map[string]string{"terminalMessageId": reconciliation.GetTerminalMessageId(), "cancellationId": reconciliation.GetCancellationId()} {
		if value != "" && validateIdentifier(field, value, maximumIdentifierBytes) != nil {
			return fmt.Errorf("reconciliation %s is invalid", field)
		}
	}
	if reconciliation.GetCancellationId() != "" && reconciliation.GetPhase() != runnerv1.JobPhase_JOB_PHASE_CANCELLING {
		return errors.New("cancellation reconciliation must be in the cancelling phase")
	}
	if reconciliation.GetPhase() == runnerv1.JobPhase_JOB_PHASE_CANCELLING && reconciliation.GetCancellationId() == "" && !terminalLeaseStatus(reconciliation.GetStatus()) {
		return errors.New("nonterminal cancelling reconciliation requires a cancellation ID")
	}
	return nil
}

func validatePendingReconciliation(pending *runnerv1.RunnerMessage, reconciliation *runnerv1.LeaseReconciliation, state journalState) error {
	if reconciliation.GetDisposition() == runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE || terminalLeaseStatus(reconciliation.GetStatus()) {
		return nil
	}
	status := reconciliation.GetStatus()
	phase := reconciliation.GetPhase()
	switch {
	case pending.GetLeaseAccepted() != nil:
		if status != runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED || phase != runnerv1.JobPhase_JOB_PHASE_ACCEPTED {
			return errors.New("lease acceptance requires authoritative accepted status and phase")
		}
	case pending.GetLeaseRejected() != nil:
		return errors.New("lease rejection acknowledgement must be stale or terminal")
	case pending.GetJobPreparing() != nil:
		if status != runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE || phase != runnerv1.JobPhase_JOB_PHASE_PREPARING {
			return errors.New("job preparing requires authoritative active/preparing state")
		}
	case pending.GetJobStarted() != nil:
		if status != runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE || phase != runnerv1.JobPhase_JOB_PHASE_RUNNING {
			return errors.New("job started requires authoritative active/running state")
		}
	case pending.GetLeaseRenewal() != nil:
		if state.Active == nil || status != runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE || phase != state.Active.Phase || (phase != runnerv1.JobPhase_JOB_PHASE_PREPARING && phase != runnerv1.JobPhase_JOB_PHASE_RUNNING) {
			return errors.New("lease renewal requires the current authoritative active phase")
		}
	case pending.GetCompleted() != nil, pending.GetFailed() != nil, pending.GetCancelled() != nil:
		return errors.New("terminal runner event acknowledgement must be stale or terminal")
	default:
		return errors.New("pending runner event is unsupported")
	}
	return nil
}

func (s *clientSession) sendHeartbeat(observedAt time.Time) error {
	state := s.client.journal.snapshot()
	if s.pendingHeartbeat == nil && len(state.PendingHeartbeat) != 0 {
		heartbeat := new(runnerv1.RunnerMessage)
		if err := proto.Unmarshal(state.PendingHeartbeat, heartbeat); err != nil {
			return err
		}
		s.pendingHeartbeat = heartbeat
	}
	if s.pendingHeartbeat != nil {
		if len(state.PendingMessage) != 0 && len(s.pendingHeartbeat.GetHeartbeat().GetActiveLeases()) != 0 {
			s.heartbeatDeferred = true
			return nil
		}
		s.heartbeatDeferred = false
		return s.send(s.pendingHeartbeat)
	}
	var leases []*runnerv1.HeartbeatLease
	if state.Active != nil && len(state.PendingMessage) == 0 {
		specification := new(runnerv1.JobSpecification)
		if err := proto.Unmarshal(state.Active.Specification, specification); err != nil {
			return err
		}
		leases = []*runnerv1.HeartbeatLease{{
			Lease:   proto.Clone(specification.GetLease()).(*runnerv1.LeaseIdentity),
			Attempt: proto.Clone(specification.GetAttempt()).(*runnerv1.AttemptIdentity),
			Phase:   state.Active.Phase,
		}}
	}
	heartbeat, err := s.client.heartbeatMessage(observedAt, leases)
	if err != nil {
		return err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(heartbeat)
	if err != nil {
		return err
	}
	if err := s.client.journal.update(func(state *journalState) error {
		if len(state.PendingHeartbeat) != 0 {
			return errors.New("runner already has an unacknowledged heartbeat")
		}
		state.PendingHeartbeat = encoded
		return nil
	}); err != nil {
		return err
	}
	s.pendingHeartbeat = heartbeat
	s.heartbeatDeferred = false
	return s.send(heartbeat)
}

func (s *clientSession) handleCancellation(envelope *runnerv1.GatewayMessage, now time.Time) error {
	cancellation := envelope.GetCancel()
	if cancellation == nil || cancellation.GetLease() == nil || cancellation.GetAttempt() == nil {
		return permanent("cancellation identity is required")
	}
	if err := validateIdentifier("cancel.cancellationId", cancellation.GetCancellationId(), maximumIdentifierBytes); err != nil {
		return permanent("%v", err)
	}
	if len(cancellation.GetReason()) > maximumReasonBytes || validateTimestamp("cancel.deadline", cancellation.GetDeadline()) != nil {
		return permanent("cancellation is invalid")
	}
	state := s.client.journal.snapshot()
	if state.Active == nil || !activeMatchesIdentity(state.Active, cancellation.GetLease(), cancellation.GetAttempt()) {
		return permanent("cancellation does not match the active lease")
	}
	encodedCancellation, err := proto.MarshalOptions{Deterministic: true}.Marshal(cancellation)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encodedCancellation)
	if state.Active.CancellationID != "" {
		if state.Active.CancellationID == cancellation.GetCancellationId() && len(state.Active.CancellationDigest) == 0 {
			// The heartbeat reconciliation can announce cancellation before the
			// corresponding command arrives; persist its semantic payload below.
		} else {
			if state.Active.CancellationID == cancellation.GetCancellationId() && bytes.Equal(state.Active.CancellationDigest, digest[:]) {
				s.client.stopWorker(context.Canceled)
				s.client.failStartResponse(context.Canceled)
				return s.advance(now)
			}
			return permanent("active lease cancellation identity or payload conflicts with the committed cancellation")
		}
	}
	if err := s.client.journal.update(func(state *journalState) error {
		state.Active.CancellationID = cancellation.GetCancellationId()
		state.Active.CancellationDeadline = cancellation.GetDeadline().AsTime()
		state.Active.CancellationDigest = bytes.Clone(digest[:])
		state.Active.Phase = runnerv1.JobPhase_JOB_PHASE_CANCELLING
		return nil
	}); err != nil {
		return err
	}
	s.client.stopWorker(context.Canceled)
	s.client.failStartResponse(context.Canceled)
	return s.advance(now)
}

func (s *clientSession) advance(now time.Time) error {
	state := s.client.journal.snapshot()
	if state.Active == nil {
		return nil
	}
	if s.client.recovering && s.reconciled && len(state.PendingMessage) == 0 {
		return s.queueRestartFailure(now)
	}
	if state.Active.CancellationID != "" {
		s.client.stopWorker(context.Canceled)
		s.client.failStartResponse(context.Canceled)
		if len(state.Active.CancellationDigest) == 0 {
			return nil
		}
		if len(state.PendingMessage) != 0 {
			return nil
		}
		if !s.client.isWorkerRunning() {
			if s.client.hasDeferredWorkerEvents() {
				return s.drainDeferred(now)
			}
			return s.queueCancellation(now, nil)
		}
		return nil
	}
	if !state.Active.ExpiresAt.After(now) {
		s.client.stopWorker(context.DeadlineExceeded)
		s.client.failStartResponse(context.DeadlineExceeded)
		if len(state.PendingMessage) != 0 {
			return nil
		}
		if !s.client.isWorkerRunning() {
			return s.queueLeaseExpired(now)
		}
		return nil
	}
	if len(state.PendingMessage) != 0 {
		return nil
	}
	if (state.Active.Phase == runnerv1.JobPhase_JOB_PHASE_PREPARING || state.Active.Phase == runnerv1.JobPhase_JOB_PHASE_RUNNING) && state.Active.ExpiresAt.Sub(now) <= s.authenticated.GetLeaseDuration().AsDuration()/2 {
		return s.queueRenewal(now)
	}
	return s.drainDeferred(now)
}

func (s *clientSession) queuePreparing(now time.Time) error {
	lease, attempt, err := activeIdentity(s.client.journal.snapshot())
	if err != nil {
		return err
	}
	return s.queueDurable(&runnerv1.RunnerMessage_JobPreparing{JobPreparing: &runnerv1.JobPreparing{Lease: lease, Attempt: attempt, StartedAt: timestamppb.New(now)}}, func(state *journalState) error {
		state.Active.Phase = runnerv1.JobPhase_JOB_PHASE_PREPARING
		return nil
	})
}

func (s *clientSession) queueRenewal(now time.Time) error {
	lease, attempt, err := activeIdentity(s.client.journal.snapshot())
	if err != nil {
		return err
	}
	renewal := &runnerv1.LeaseRenewal{Lease: lease, Attempt: attempt, RequestedExtension: durationpb.New(s.authenticated.GetLeaseDuration().AsDuration()), ObservedAt: timestamppb.New(now)}
	return s.queueDurable(&runnerv1.RunnerMessage_LeaseRenewal{LeaseRenewal: renewal}, nil)
}

func (s *clientSession) handleWorkerEvent(event workerEvent) error {
	if event.evidence != nil {
		return s.sendWorkerEvidence(event.evidence)
	}
	if event.result != nil {
		s.client.markWorkerStopped()
		if event.finalEvidence != nil {
			_ = s.sendWorkerEvidence(event.finalEvidence)
		}
		if event.finalUsage != nil {
			_ = s.sendWorkerEvidence(event.finalUsage)
		}
	}
	state := s.client.journal.snapshot()
	if state.Active == nil {
		if event.start != nil {
			event.start <- errors.New("lease is no longer active")
		}
		if event.result != nil {
			closeCompleteLog(event.result.CompleteLog)
			s.client.clearCompleteLogTarget()
		}
		return nil
	}
	if len(state.PendingMessage) != 0 {
		s.client.deferWorkerEvent(event)
		return nil
	}
	if event.start != nil {
		if state.Active.CancellationID != "" {
			event.start <- context.Canceled
			return nil
		}
		lease, attempt, err := activeIdentity(state)
		if err != nil {
			event.start <- err
			return err
		}
		s.client.setStartResponse(event.start)
		return s.queueDurable(&runnerv1.RunnerMessage_JobStarted{JobStarted: &runnerv1.JobStarted{Lease: lease, Attempt: attempt, StartedAt: timestamppb.New(s.client.now().UTC())}}, func(state *journalState) error {
			state.Active.Phase = runnerv1.JobPhase_JOB_PHASE_RUNNING
			return nil
		})
	}
	if event.result != nil {
		state = s.client.journal.snapshot()
		if state.Active == nil {
			closeCompleteLog(event.result.CompleteLog)
			s.client.clearCompleteLogTarget()
			return nil
		}
		var err error
		if state.Active.CancellationID != "" {
			if len(state.Active.CancellationDigest) == 0 {
				s.client.deferWorkerEvent(event)
				return nil
			}
			err = s.queueCancellation(s.client.now().UTC(), event.result)
		} else if !state.Active.ExpiresAt.After(s.client.now().UTC()) {
			err = s.queueLeaseExpired(s.client.now().UTC())
		} else {
			err = s.queueResult(*event.result)
		}
		if len(s.client.journal.snapshot().PendingMessage) != 0 {
			closeCompleteLog(event.result.CompleteLog)
			s.client.clearCompleteLogTarget()
		} else if err != nil {
			s.client.deferWorkerEvent(event)
		}
		return err
	}
	return errors.New("worker event is empty")
}

func (s *clientSession) drainDeferred(now time.Time) error {
	for len(s.client.journal.snapshot().PendingMessage) == 0 {
		event, exists := s.client.popDeferredWorkerEvent()
		if !exists {
			return nil
		}
		if err := s.handleWorkerEvent(event); err != nil {
			return err
		}
	}
	return nil
}

func (s *clientSession) discardDeferred(reason error) {
	for _, event := range s.client.takeDeferredWorkerEvents() {
		if event.start != nil {
			event.start <- reason
		}
		if event.result != nil {
			closeCompleteLog(event.result.CompleteLog)
		}
	}
}

func (c *Client) deferWorkerEvent(event workerEvent) {
	c.deferredMu.Lock()
	defer c.deferredMu.Unlock()
	c.deferredWorkerEvents = append(c.deferredWorkerEvents, event)
}

func (c *Client) popDeferredWorkerEvent() (workerEvent, bool) {
	c.deferredMu.Lock()
	defer c.deferredMu.Unlock()
	if len(c.deferredWorkerEvents) == 0 {
		return workerEvent{}, false
	}
	event := c.deferredWorkerEvents[0]
	c.deferredWorkerEvents = c.deferredWorkerEvents[1:]
	return event, true
}

func (c *Client) takeDeferredWorkerEvents() []workerEvent {
	c.deferredMu.Lock()
	defer c.deferredMu.Unlock()
	events := c.deferredWorkerEvents
	c.deferredWorkerEvents = nil
	return events
}

func (c *Client) hasDeferredWorkerEvents() bool {
	c.deferredMu.Lock()
	defer c.deferredMu.Unlock()
	return len(c.deferredWorkerEvents) != 0
}

func (c *Client) deferredWorkerEventCount() int {
	c.deferredMu.Lock()
	defer c.deferredMu.Unlock()
	return len(c.deferredWorkerEvents)
}

func (s *clientSession) queueResult(result execution.Result) error {
	lease, attempt, err := activeIdentity(s.client.journal.snapshot())
	if err != nil {
		return err
	}
	startedAt, completedAt, err := normalizedTerminalTimes(result.StartedAt, result.CompletedAt)
	if err != nil {
		return err
	}
	var completeLog *runnerv1.LogObject
	usage := resultResourceUsage(result)
	if target := s.client.completeLogTarget(lease, attempt); target != nil {
		ctx := s.rootContext
		if ctx == nil {
			ctx = context.Background()
		}
		if s.client.logUploader == nil {
			err = errors.New("complete log uploader is unavailable")
		} else {
			completeLog, err = s.client.logUploader.Upload(ctx, target, result.CompleteLog)
		}
		if err != nil {
			failed := &runnerv1.JobFailed{
				Lease: lease, Attempt: attempt, FailedAt: timestamppb.New(completedAt),
				Usage: usage,
				Failure: &runnerv1.FailureDetail{
					Category:  runnerv1.FailureCategory_FAILURE_CATEGORY_INFRASTRUCTURE,
					Stage:     runnerv1.FailureStage_FAILURE_STAGE_RESULT_UPLOAD,
					Code:      "complete_log_upload_failed",
					Summary:   "complete log evidence could not be uploaded",
					Retryable: true,
				},
			}
			return s.queueDurable(&runnerv1.RunnerMessage_Failed{Failed: failed}, nil)
		}
	}
	if result.Passed() || result.Classification == execution.ClassificationWorkloadFailure {
		outcome := runnerv1.ResultOutcome_RESULT_OUTCOME_FAILED
		if result.Passed() {
			outcome = runnerv1.ResultOutcome_RESULT_OUTCOME_PASSED
		}
		structured := &runnerv1.StructuredResult{Outcome: outcome, Usage: usage, CompleteLog: completeLog, StartedAt: timestamppb.New(startedAt), CompletedAt: timestamppb.New(completedAt)}
		if result.Execution != nil && result.Execution.ExitCode != nil {
			value := int32(*result.Execution.ExitCode)
			structured.ProcessExitCode = &value
		}
		completed := &runnerv1.JobCompleted{Lease: lease, Attempt: attempt, Result: structured}
		return s.queueDurable(&runnerv1.RunnerMessage_Completed{Completed: completed}, nil)
	}
	failure := resultFailure(result)
	failed := &runnerv1.JobFailed{Lease: lease, Attempt: attempt, Failure: failure, Usage: usage, CompleteLog: completeLog, FailedAt: timestamppb.New(completedAt)}
	return s.queueDurable(&runnerv1.RunnerMessage_Failed{Failed: failed}, nil)
}

func normalizedTerminalTimes(startedAt, completedAt time.Time) (time.Time, time.Time, error) {
	if startedAt.IsZero() || completedAt.IsZero() {
		return time.Time{}, time.Time{}, errors.New("terminal result timestamps are required")
	}
	if completedAt.Before(startedAt) {
		return time.Time{}, time.Time{}, errors.New("terminal result completedAt precedes startedAt")
	}
	startedAt = normalizedTerminalTime(startedAt)
	completedAt = normalizedTerminalTime(completedAt)
	return startedAt, completedAt, nil
}

func normalizedTerminalTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func resultResourceUsage(result execution.Result) *runnerv1.ResourceUsage {
	if result.Usage.MeasuredResources == nil {
		return nil
	}
	return resourceUsageMessage(*result.Usage.MeasuredResources)
}

func closeCompleteLog(completeLog *execution.CompleteLog) {
	if completeLog == nil || completeLog.Archive == nil {
		return
	}
	_ = completeLog.Archive.Close()
	completeLog.Archive = nil
}

func (s *clientSession) queueCancellation(now time.Time, result *execution.Result) error {
	state := s.client.journal.snapshot()
	lease, attempt, err := activeIdentity(state)
	if err != nil {
		return err
	}
	cleanupCompleted := result == nil || (result.Cleanup != nil && result.Cleanup.Succeeded)
	cancelled := &runnerv1.JobCancelled{Lease: lease, Attempt: attempt, CancellationId: state.Active.CancellationID, CancelledAt: timestamppb.New(normalizedTerminalTime(now)), CleanupCompleted: cleanupCompleted}
	if result != nil && result.Cleanup != nil && !result.Cleanup.Succeeded {
		cancelled.CleanupFailure = &runnerv1.FailureDetail{Category: runnerv1.FailureCategory_FAILURE_CATEGORY_INFRASTRUCTURE, Stage: runnerv1.FailureStage_FAILURE_STAGE_CLEANUP, Code: "cleanup_failed", Summary: boundedSummary(result.Cleanup.Error), Retryable: true}
	}
	return s.queueDurable(&runnerv1.RunnerMessage_Cancelled{Cancelled: cancelled}, nil)
}

func (s *clientSession) queueLeaseExpired(now time.Time) error {
	lease, attempt, err := activeIdentity(s.client.journal.snapshot())
	if err != nil {
		return err
	}
	failed := &runnerv1.JobFailed{Lease: lease, Attempt: attempt, FailedAt: timestamppb.New(normalizedTerminalTime(now)), Failure: &runnerv1.FailureDetail{Category: runnerv1.FailureCategory_FAILURE_CATEGORY_INFRASTRUCTURE, Stage: runnerv1.FailureStage_FAILURE_STAGE_LEASE, Code: "lease_expired", Summary: "authoritative runner lease expired", Retryable: true}}
	return s.queueDurable(&runnerv1.RunnerMessage_Failed{Failed: failed}, nil)
}

func (s *clientSession) queueRestartFailure(now time.Time) error {
	if s.client.activeRestartEvidence() != nil {
		// Recovery evidence remains durable until the gateway supplies a fresh,
		// attempt-scoped upload capability. Never replace it with a terminal
		// event that omits the complete log or cumulative measured usage.
		return nil
	}
	lease, attempt, err := activeIdentity(s.client.journal.snapshot())
	if err != nil {
		return err
	}
	failed := &runnerv1.JobFailed{Lease: lease, Attempt: attempt, FailedAt: timestamppb.New(normalizedTerminalTime(now)), Failure: &runnerv1.FailureDetail{Category: runnerv1.FailureCategory_FAILURE_CATEGORY_INFRASTRUCTURE, Stage: runnerv1.FailureStage_FAILURE_STAGE_EXECUTION, Code: "runner_restarted", Summary: "runner restarted with an authoritative lease whose execution outcome is uncertain", Retryable: true}}
	return s.queueDurable(&runnerv1.RunnerMessage_Failed{Failed: failed}, nil)
}

func (s *clientSession) clearPending() error {
	return s.client.journal.update(func(state *journalState) error {
		state.PendingMessage = nil
		return nil
	})
}

func (c *Client) startWorker(ctx context.Context) error {
	c.workerMu.Lock()
	if c.workerRunning {
		c.workerMu.Unlock()
		return errors.New("remote worker is already running")
	}
	state := c.journal.snapshot()
	if state.Active == nil || c.worker == nil {
		c.workerMu.Unlock()
		return errors.New("remote worker cannot start without an active job")
	}
	specification := new(runnerv1.JobSpecification)
	if err := proto.Unmarshal(state.Active.Specification, specification); err != nil {
		c.workerMu.Unlock()
		return err
	}
	workerContext, cancel := context.WithCancel(ctx)
	observer := newLiveExecutionObserver(c, specification)
	workerContext = execution.WithObserver(workerContext, observer)
	c.workerRunning = true
	c.workerCancel = cancel
	c.workerWG.Add(1)
	c.workerMu.Unlock()
	go func() {
		defer c.workerWG.Done()
		result := c.worker.Execute(workerContext, specification, func(startContext context.Context, _ execution.ExecutionStart) error {
			response := make(chan error, 1)
			select {
			case c.workerEvents <- workerEvent{start: response}:
			case <-startContext.Done():
				return startContext.Err()
			}
			select {
			case err := <-response:
				return err
			case <-startContext.Done():
				return startContext.Err()
			}
		})
		var finalUsage *workerEvidenceEvent
		if result.Usage.MeasuredResources != nil {
			finalUsage = observer.finalUsageEvent(*result.Usage.MeasuredResources)
		}
		select {
		case c.workerEvents <- workerEvent{result: &result, finalEvidence: observer.finalDroppedEvent(), finalUsage: finalUsage}:
		case <-ctx.Done():
			closeCompleteLog(result.CompleteLog)
		}
	}()
	return nil
}

func (c *Client) discardQueuedWorkerEvents(reason error) {
	for {
		select {
		case event := <-c.workerEvents:
			if event.start != nil {
				event.start <- reason
			}
			if event.result != nil {
				closeCompleteLog(event.result.CompleteLog)
			}
		default:
			return
		}
	}
}

func (c *Client) stopWorker(_ error) {
	c.workerMu.Lock()
	defer c.workerMu.Unlock()
	if c.workerCancel != nil {
		c.workerCancel()
	}
}

func (c *Client) markWorkerStopped() {
	c.workerMu.Lock()
	defer c.workerMu.Unlock()
	c.workerRunning = false
	c.workerCancel = nil
}

func (c *Client) isWorkerRunning() bool {
	c.workerMu.Lock()
	defer c.workerMu.Unlock()
	return c.workerRunning
}

func (c *Client) setStartResponse(response chan error) {
	c.workerMu.Lock()
	defer c.workerMu.Unlock()
	c.startResponse = response
}

func (c *Client) completeStartResponse(err error) {
	c.workerMu.Lock()
	response := c.startResponse
	c.startResponse = nil
	c.workerMu.Unlock()
	if response != nil {
		response <- err
	}
}

func (c *Client) failStartResponse(err error) {
	c.completeStartResponse(err)
}

func activeIdentity(state journalState) (*runnerv1.LeaseIdentity, *runnerv1.AttemptIdentity, error) {
	if state.Active == nil {
		return nil, nil, errors.New("active lease is missing")
	}
	specification := new(runnerv1.JobSpecification)
	if err := proto.Unmarshal(state.Active.Specification, specification); err != nil {
		return nil, nil, err
	}
	return proto.Clone(specification.GetLease()).(*runnerv1.LeaseIdentity), proto.Clone(specification.GetAttempt()).(*runnerv1.AttemptIdentity), nil
}

func activeMatchesIdentity(active *journalJob, lease *runnerv1.LeaseIdentity, attempt *runnerv1.AttemptIdentity) bool {
	if active == nil {
		return false
	}
	specification := new(runnerv1.JobSpecification)
	if proto.Unmarshal(active.Specification, specification) != nil {
		return false
	}
	return sameLeaseAttempt(specification.GetLease(), specification.GetAttempt(), lease, attempt)
}

func sameLeaseAttempt(leftLease *runnerv1.LeaseIdentity, leftAttempt *runnerv1.AttemptIdentity, rightLease *runnerv1.LeaseIdentity, rightAttempt *runnerv1.AttemptIdentity) bool {
	return leftLease != nil && leftAttempt != nil && rightLease != nil && rightAttempt != nil && leftLease.GetLeaseId() == rightLease.GetLeaseId() && leftLease.GetJobId() == rightLease.GetJobId() && leftLease.GetExecutionId() == rightLease.GetExecutionId() && leftAttempt.GetAttemptId() == rightAttempt.GetAttemptId() && leftAttempt.GetAttemptNumber() == rightAttempt.GetAttemptNumber() && leftAttempt.GetReleaseCandidateId() == rightAttempt.GetReleaseCandidateId() && leftAttempt.GetMatrixEntryId() == rightAttempt.GetMatrixEntryId()
}

func runnerMessageIdentity(message *runnerv1.RunnerMessage) (*runnerv1.LeaseIdentity, *runnerv1.AttemptIdentity) {
	switch {
	case message.GetLeaseAccepted() != nil:
		return message.GetLeaseAccepted().GetLease(), message.GetLeaseAccepted().GetAttempt()
	case message.GetLeaseRejected() != nil:
		return message.GetLeaseRejected().GetLease(), message.GetLeaseRejected().GetAttempt()
	case message.GetLeaseRenewal() != nil:
		return message.GetLeaseRenewal().GetLease(), message.GetLeaseRenewal().GetAttempt()
	case message.GetJobPreparing() != nil:
		return message.GetJobPreparing().GetLease(), message.GetJobPreparing().GetAttempt()
	case message.GetJobStarted() != nil:
		return message.GetJobStarted().GetLease(), message.GetJobStarted().GetAttempt()
	case message.GetCompleted() != nil:
		return message.GetCompleted().GetLease(), message.GetCompleted().GetAttempt()
	case message.GetFailed() != nil:
		return message.GetFailed().GetLease(), message.GetFailed().GetAttempt()
	case message.GetCancelled() != nil:
		return message.GetCancelled().GetLease(), message.GetCancelled().GetAttempt()
	default:
		return nil, nil
	}
}

func terminalLeaseStatus(status runnerv1.LeaseStatus) bool {
	return status == runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED || status == runnerv1.LeaseStatus_LEASE_STATUS_CANCELLED || status == runnerv1.LeaseStatus_LEASE_STATUS_EXPIRED || status == runnerv1.LeaseStatus_LEASE_STATUS_RELEASED
}

func jobPhaseRank(phase runnerv1.JobPhase) int {
	switch phase {
	case runnerv1.JobPhase_JOB_PHASE_ACCEPTED:
		return 1
	case runnerv1.JobPhase_JOB_PHASE_PREPARING:
		return 2
	case runnerv1.JobPhase_JOB_PHASE_RUNNING:
		return 3
	case runnerv1.JobPhase_JOB_PHASE_CANCELLING:
		return 4
	default:
		return 0
	}
}

func boundedSummary(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "runner event failed"
	}
	if len(value) > maximumReasonBytes {
		value = value[:maximumReasonBytes]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}

func resultFailure(result execution.Result) *runnerv1.FailureDetail {
	detail := &runnerv1.FailureDetail{Category: runnerv1.FailureCategory_FAILURE_CATEGORY_INFRASTRUCTURE, Stage: failureStage(result.Phase), Code: "runner_execution_failed", Summary: "remote execution failed", Retryable: true}
	if result.Failure != nil {
		detail.Code = result.Failure.Code
		detail.Summary = boundedSummary(result.Failure.Message)
	}
	switch result.Classification {
	case execution.ClassificationInvalidJob:
		detail.Category = runnerv1.FailureCategory_FAILURE_CATEGORY_POLICY
		detail.Retryable = false
	case execution.ClassificationWorkloadFailure:
		detail.Category = runnerv1.FailureCategory_FAILURE_CATEGORY_PLUGIN
		detail.Retryable = false
	case execution.ClassificationCancelled:
		detail.Code = "job_cancelled"
		detail.Retryable = true
	case execution.ClassificationTimedOut:
		detail.Code = "job_timed_out"
		detail.Retryable = false
	}
	return detail
}

func failureStage(phase execution.Phase) runnerv1.FailureStage {
	switch phase {
	case execution.PhaseValidation, execution.PhaseResolution:
		return runnerv1.FailureStage_FAILURE_STAGE_LEASE
	case execution.PhasePreparation:
		return runnerv1.FailureStage_FAILURE_STAGE_PREPARATION
	case execution.PhaseCleanup, execution.PhaseCollection:
		return runnerv1.FailureStage_FAILURE_STAGE_CLEANUP
	default:
		return runnerv1.FailureStage_FAILURE_STAGE_EXECUTION
	}
}

func (s *clientSession) String() string {
	return fmt.Sprintf("runner session for %s", s.client.config.RunnerID)
}
