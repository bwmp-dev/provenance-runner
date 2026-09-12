package gatewayclient

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var errSecretDeliveryUnavailable = errors.New("test-secret delivery unavailable")
var errSecretConnectionLost = errors.New("test-secret connection lost")

const maximumSecretDeliveryBytes = 98304

func (c *Client) stopSecretWorker(generation uint64) {
	c.workerMu.Lock()
	defer c.workerMu.Unlock()
	if c.workerSecretCancel != nil && c.workerSecretGeneration == generation {
		c.workerSecretCancel()
	}
}

type workerSecretRequest struct {
	ctx        context.Context
	generation uint64
	response   chan secretResponse
}

type secretResponse struct {
	files     *testsecrets.Files
	expiresAt time.Time
	err       error
}

type pendingSecretRequest struct {
	worker    *workerSecretRequest
	requestID string
	job       *runnerv1.JobSpecification // Metadata only; never a delivery.
}

func finishSecretRequest(request *workerSecretRequest, response secretResponse) {
	select {
	case request.response <- response:
	case <-request.ctx.Done():
		if response.files != nil {
			_ = response.files.Close()
		}
	}
}

// The original worker generation is captured, not refreshed after reconnect.
// A new connection may never resume a pending old-stream secret request.
func (c *Client) requestTestSecretFiles(ctx context.Context, generation uint64) (*testsecrets.Files, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	request := &workerSecretRequest{ctx: ctx, generation: generation, response: make(chan secretResponse)}
	if generation == 0 || generation != c.sessionGeneration.Load() {
		return nil, time.Time{}, errSecretDeliveryUnavailable
	}
	select {
	case c.workerEvents <- workerEvent{secretRequest: request}:
	case <-ctx.Done():
		return nil, time.Time{}, errSecretDeliveryUnavailable
	}
	select {
	case response := <-request.response:
		return response.files, response.expiresAt, response.err
	case <-ctx.Done():
		return nil, time.Time{}, errSecretDeliveryUnavailable
	}
}

func (s *clientSession) beginSecretRequest(request *workerSecretRequest) error {
	refuse := func() error {
		finishSecretRequest(request, secretResponse{err: errSecretDeliveryUnavailable})
		return nil
	}
	if !s.testSecretsV1 || !s.jobCorrelationV1 || !s.reconciled || request.ctx.Err() != nil || request.generation != s.generation || s.pendingSecret != nil {
		return refuse()
	}
	state := s.client.journal.snapshot()
	if state.Active == nil || state.Active.Phase != runnerv1.JobPhase_JOB_PHASE_PREPARING || state.Active.CancellationID != "" || !state.Active.ExpiresAt.After(s.client.now()) {
		return refuse()
	}
	if len(state.PendingMessage) != 0 {
		s.client.deferWorkerEvent(workerEvent{secretRequest: request})
		return nil
	}
	job := new(runnerv1.JobSpecification)
	if proto.Unmarshal(state.Active.Specification, job) != nil || len(job.GetTestSecrets()) == 0 || job.GetAttempt() == nil || job.GetLease().GetExpiresAt() == nil || !job.GetLease().GetExpiresAt().AsTime().Equal(state.Active.ExpiresAt) || validateOfferJobCorrelation(job, s.client.config.ExpectedScope, true) != nil {
		return refuse()
	}
	if testsecrets.ValidateSelection(job) != nil {
		return refuse()
	}
	sequence := s.client.ephemeralSequence.Add(1)
	if sequence == 0 || sequence > math.MaxInt64 {
		return refuse()
	}
	id := fmt.Sprintf("secret-%016x-%016x", s.generation, sequence)
	message := &runnerv1.RunnerMessage{MessageId: id, SentAt: timestamppb.New(s.client.now()), Payload: &runnerv1.RunnerMessage_TestSecretsRequest{TestSecretsRequest: &runnerv1.TestSecretsRequest{Lease: proto.Clone(job.Lease).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(job.Attempt).(*runnerv1.AttemptIdentity)}}}
	if proto.Size(message) > MaximumMessageBytes {
		return refuse()
	}
	s.pendingSecret = &pendingSecretRequest{worker: request, requestID: id, job: job}
	if err := s.send(message); err != nil {
		s.pendingSecret = nil
		_ = refuse()
		return err
	}
	return nil
}

func (s *clientSession) receiveSecretDelivery(message *runnerv1.GatewayMessage) error {
	defer clearTestSecretDelivery(message)
	pending := s.pendingSecret
	s.pendingSecret = nil
	if pending == nil {
		return permanent("unsolicited test-secret delivery")
	}
	failure := func() error {
		finishSecretRequest(pending.worker, secretResponse{err: errSecretDeliveryUnavailable})
		return permanent("test-secret delivery refused")
	}
	if !s.testSecretsV1 {
		return failure()
	}
	state := s.client.journal.snapshot()
	if pending.worker.ctx.Err() != nil || pending.worker.generation != s.generation || !s.reconciled || state.Active == nil || state.Active.CancellationID != "" || state.Active.Phase != runnerv1.JobPhase_JOB_PHASE_PREPARING || !activeMatchesIdentity(state.Active, pending.job.Lease, pending.job.Attempt) || !state.Active.ExpiresAt.After(s.client.now()) || validateGatewayEnvelope(message, s.client.now()) != nil {
		return failure()
	}
	current := new(runnerv1.JobSpecification)
	if proto.Unmarshal(state.Active.Specification, current) != nil || current.GetLease().GetExpiresAt() == nil || !current.GetLease().GetExpiresAt().AsTime().Equal(state.Active.ExpiresAt) {
		return failure()
	}
	expected := proto.Clone(pending.job).(*runnerv1.JobSpecification)
	expected.Lease.ExpiresAt = current.Lease.ExpiresAt
	if !proto.Equal(current, expected) {
		return failure()
	}
	files, expiry, err := sealSecretDelivery(pending.job, pending.requestID, message, s.client.now())
	if err != nil {
		return failure()
	}
	if expiry.After(state.Active.ExpiresAt) {
		_ = files.Close()
		return failure()
	}
	finishSecretRequest(pending.worker, secretResponse{files: files, expiresAt: expiry})
	return nil
}

func (s *clientSession) abandonSecretRequest() {
	if pending := s.pendingSecret; pending != nil {
		s.pendingSecret = nil
		finishSecretRequest(pending.worker, secretResponse{err: errSecretDeliveryUnavailable})
	}
}
