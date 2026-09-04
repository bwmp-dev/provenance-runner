package gatewayclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type restartRecoveryUploader struct {
	calls       int
	failures    int
	substitute  bool
	targetURIs  []string
	archiveSize []int64
}

func (u *restartRecoveryUploader) Upload(_ context.Context, target *completeLogTarget, completeLog *execution.CompleteLog) (*runnerv1.LogObject, error) {
	u.calls++
	u.targetURIs = append(u.targetURIs, target.uri)
	if u.failures > 0 {
		u.failures--
		return nil, errors.New("simulated secret-bearing transport failure")
	}
	digest, size, err := validateUploadArchive(completeLog)
	if err != nil {
		return nil, err
	}
	u.archiveSize = append(u.archiveSize, size)
	objectKey := target.objectKey
	if u.substitute {
		objectKey = "substituted/execution/attempt/log.gz"
	}
	return &runnerv1.LogObject{
		ObjectKey: objectKey, Digest: &runnerv1.Digest{Algorithm: runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest},
		CompressedSizeBytes: uint64(size), ContentType: completeLogUploadContentType,
	}, nil
}

type restartRecoveryHarness struct {
	client  *Client
	session *clientSession
	offer   *runnerv1.LeaseOffer
	sent    []*runnerv1.RunnerMessage
}

func newRestartRecoveryHarness(t *testing.T, now time.Time, uploader completeLogUploader) *restartRecoveryHarness {
	t.Helper()
	config := validConfig()
	config.journalFile = filepath.Join(t.TempDir(), "journal.json")
	journal, err := openJournal(config.journalFile)
	if err != nil {
		t.Fatal(err)
	}
	offer := validLeaseOffer(now)
	offer.Job.JobCorrelation = validJobCorrelation(offer)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, 32), JobCorrelationV1: true, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	store, err := createRestartEvidenceStore(config.journalFile, offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
	if err != nil {
		t.Fatal(err)
	}
	store.observeLog(execution.LiveLogEntry{Stream: "stdout", Data: []byte("safe output before restart\n"), Redacted: true})
	store.observeLog(execution.LiveLogEntry{Stream: "stderr", Data: []byte("safe diagnostic\n"), Redacted: true})
	store.observeUsage(execution.ResourceUsage{CPUTime: 3 * time.Second, PeakMemoryBytes: 4096, DiskReadBytes: 20, DiskWriteBytes: 8})
	store.observeUsage(execution.ResourceUsage{CPUTime: time.Second, PeakMemoryBytes: 1024, DiskReadBytes: 30, NetworkReceiveBytes: 7})
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	client, err := newClientWithWorker(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.now = func() time.Time { return now }
	client.logUploader = uploader
	harness := &restartRecoveryHarness{client: client, offer: offer}
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	harness.session = &clientSession{client: client, authenticated: authenticated, restartUploadRecovery: true, rootContext: context.Background(), send: func(message *runnerv1.RunnerMessage) error {
		harness.sent = append(harness.sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}}
	return harness
}

func (h *restartRecoveryHarness) sendHeartbeat(t *testing.T, now time.Time) *runnerv1.RunnerMessage {
	t.Helper()
	if err := h.session.sendHeartbeat(now); err != nil {
		t.Fatal(err)
	}
	return h.session.pendingHeartbeat
}

func (h *restartRecoveryHarness) heartbeatAcknowledgement(heartbeat *runnerv1.RunnerMessage, now time.Time, upload *runnerv1.ObjectUpload) *runnerv1.HeartbeatAcknowledgement {
	return &runnerv1.HeartbeatAcknowledgement{
		RunnerMessageId: heartbeat.GetMessageId(), Sequence: heartbeat.GetHeartbeat().GetSequence(), CommittedAt: timestamppb.New(now),
		Reconciliations: []*runnerv1.LeaseReconciliation{{
			Lease: proto.Clone(h.offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(h.offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity),
			Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, Status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE,
			Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, CompleteLogUpload: upload,
		}},
	}
}

func TestRestartRecoveryUploadsDurableEvidenceAndJournalsCanonicalTerminalBeforeSend(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	uploader := new(restartRecoveryUploader)
	harness := newRestartRecoveryHarness(t, now, uploader)
	heartbeat := harness.sendHeartbeat(t, now)
	upload := validCompleteLogUpload(now)
	if err := harness.session.handleHeartbeatAcknowledgement(harness.heartbeatAcknowledgement(heartbeat, now, upload), now); err != nil {
		t.Fatal(err)
	}
	if uploader.calls != 1 || len(harness.sent) != 2 {
		t.Fatalf("upload calls = %d sent = %d", uploader.calls, len(harness.sent))
	}
	failed := harness.sent[1].GetFailed()
	if failed == nil || failed.GetFailure().GetCode() != "runner_restarted" || failed.GetFailure().GetStage() != runnerv1.FailureStage_FAILURE_STAGE_EXECUTION || !failed.GetFailure().GetRetryable() {
		t.Fatalf("restart failure = %#v", failed)
	}
	if failed.GetCompleteLog() == nil || failed.GetUsage().GetCpuTime().AsDuration() != 3*time.Second || failed.GetUsage().GetPeakMemoryBytes() != 4096 || failed.GetUsage().GetDiskReadBytes() != 30 || failed.GetUsage().GetDiskWriteBytes() != 8 || failed.GetUsage().GetNetworkReceiveBytes() != 7 {
		t.Fatalf("terminal evidence = log %#v usage %#v", failed.GetCompleteLog(), failed.GetUsage())
	}
	pending := new(runnerv1.RunnerMessage)
	if err := proto.Unmarshal(harness.client.journal.snapshot().PendingMessage, pending); err != nil || !proto.Equal(pending, harness.sent[1]) {
		t.Fatalf("terminal message was not journaled before send: %v", err)
	}
	encoded, err := proto.Marshal(pending)
	if err != nil || bytes.Contains(encoded, []byte("signature=secret")) || bytes.Contains(encoded, []byte("logs.example")) {
		t.Fatalf("terminal journal retained upload capability: %q, %v", encoded, err)
	}
	assertNoRestartUploadSecret(t, filepath.Dir(harness.client.config.journalFile), "signature=secret")
	ack := &runnerv1.RunnerEventAcknowledgement{RunnerMessageId: pending.GetMessageId(), CommittedAt: timestamppb.New(now), Reconciliation: &runnerv1.LeaseReconciliation{
		Lease: failed.GetLease(), Attempt: failed.GetAttempt(), Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED,
		Status: runnerv1.LeaseStatus_LEASE_STATUS_RELEASED, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, TerminalMessageId: pending.GetMessageId(),
	}}
	if err := harness.session.handleEventAcknowledgement(ack, now); err != nil {
		t.Fatal(err)
	}
	if harness.client.journal.snapshot().Active != nil {
		t.Fatal("terminal acknowledgement did not clear active state")
	}
	if _, err := os.Lstat(restartEvidencePath(harness.client.config.journalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restart evidence survived terminal acknowledgement: %v", err)
	}
}

func TestRestartRecoveryRejectsCapabilityInEventAcknowledgement(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	uploader := new(restartRecoveryUploader)
	harness := newRestartRecoveryHarness(t, now, uploader)
	if err := harness.session.queueRenewal(now); err != nil {
		t.Fatal(err)
	}
	renewal := harness.sent[len(harness.sent)-1]
	pending := bytes.Clone(harness.client.journal.snapshot().PendingMessage)
	acknowledgement := eventAcknowledgement(now, "renewal-ack", renewal, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_RUNNING).GetEventAcknowledgement()
	acknowledgement.Reconciliation.CompleteLogUpload = validCompleteLogUpload(now)
	if err := harness.session.handleEventAcknowledgement(acknowledgement, now); err == nil || !strings.Contains(err.Error(), "must not contain") {
		t.Fatalf("event acknowledgement capability error = %v", err)
	}
	if uploader.calls != 0 || harness.client.completeLogTarget(harness.offer.GetJob().GetLease(), harness.offer.GetJob().GetAttempt()) != nil || !bytes.Equal(pending, harness.client.journal.snapshot().PendingMessage) {
		t.Fatalf("invalid event acknowledgement mutated recovery state: calls=%d", uploader.calls)
	}
	acknowledgement.Reconciliation.CompleteLogUpload = nil
	if err := harness.session.handleEventAcknowledgement(acknowledgement, now); err != nil {
		t.Fatal(err)
	}
	acknowledgement.Reconciliation.CompleteLogUpload = validCompleteLogUpload(now)
	if err := harness.session.handleEventAcknowledgement(acknowledgement, now); err == nil || !strings.Contains(err.Error(), "must not contain") {
		t.Fatalf("settled event acknowledgement capability error = %v", err)
	}
	if uploader.calls != 0 || harness.client.completeLogTarget(harness.offer.GetJob().GetLease(), harness.offer.GetJob().GetAttempt()) != nil {
		t.Fatalf("invalid settled event acknowledgement mutated recovery state: calls=%d", uploader.calls)
	}
}

func TestRestartRecoveryUploadFailureRequiresFreshCapabilityAndRetainsEvidence(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	uploader := &restartRecoveryUploader{failures: 1}
	harness := newRestartRecoveryHarness(t, now, uploader)
	firstHeartbeat := harness.sendHeartbeat(t, now)
	first := validCompleteLogUpload(now)
	first.Uri = "https://logs.example/staging/execution/attempt/log.gz?signature=first-secret"
	if err := harness.session.handleHeartbeatAcknowledgement(harness.heartbeatAcknowledgement(firstHeartbeat, now, first), now); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("first upload error = %v", err)
	}
	if harness.client.completeLogTarget(harness.offer.GetJob().GetLease(), harness.offer.GetJob().GetAttempt()) != nil || len(harness.client.journal.snapshot().PendingMessage) != 0 {
		t.Fatal("failed upload retained a capability or journaled an incomplete terminal event")
	}
	recovered, err := harness.client.activeRestartEvidence().snapshot(context.Background())
	if err != nil {
		t.Fatalf("failed upload discarded durable evidence: %v", err)
	}
	closeCompleteLog(recovered.CompleteLog)
	secondNow := now.Add(time.Second)
	secondHeartbeat := harness.sendHeartbeat(t, secondNow)
	second := validCompleteLogUpload(secondNow)
	second.Uri = "https://logs.example/staging/execution/attempt/log.gz?signature=fresh-secret"
	if err := harness.session.handleHeartbeatAcknowledgement(harness.heartbeatAcknowledgement(secondHeartbeat, secondNow, second), secondNow); err != nil {
		t.Fatal(err)
	}
	if uploader.calls != 2 || uploader.targetURIs[0] == uploader.targetURIs[1] || harness.sent[len(harness.sent)-1].GetFailed() == nil {
		t.Fatalf("fresh retry calls=%d targets=%q", uploader.calls, uploader.targetURIs)
	}
	assertNoRestartUploadSecret(t, filepath.Dir(harness.client.config.journalFile), "first-secret")
	assertNoRestartUploadSecret(t, filepath.Dir(harness.client.config.journalFile), "fresh-secret")
}

func TestRestartRecoveryReplaysJournaledTerminalWithoutReupload(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	uploader := new(restartRecoveryUploader)
	harness := newRestartRecoveryHarness(t, now, uploader)
	heartbeat := harness.sendHeartbeat(t, now)
	harness.session.send = func(message *runnerv1.RunnerMessage) error {
		harness.sent = append(harness.sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		if message.GetFailed() != nil {
			return errors.New("simulated stream close")
		}
		return nil
	}
	if err := harness.session.handleHeartbeatAcknowledgement(harness.heartbeatAcknowledgement(heartbeat, now, validCompleteLogUpload(now)), now); err == nil {
		t.Fatal("terminal send failure was not returned")
	}
	pending := bytes.Clone(harness.client.journal.snapshot().PendingMessage)
	if uploader.calls != 1 || len(pending) == 0 {
		t.Fatalf("upload calls=%d pending=%d", uploader.calls, len(pending))
	}
	harness.session.send = func(message *runnerv1.RunnerMessage) error {
		harness.sent = append(harness.sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}
	if err := harness.session.replayPending(); err != nil {
		t.Fatal(err)
	}
	if uploader.calls != 1 {
		t.Fatalf("journal replay reuploaded durable evidence: calls=%d", uploader.calls)
	}
	replayed, err := proto.Marshal(harness.sent[len(harness.sent)-1])
	if err != nil || !bytes.Equal(replayed, pending) {
		t.Fatalf("replayed terminal differs from journal: %v", err)
	}
}

func TestRestartRecoveryRejectsInvalidOrSubstitutedUploadResponses(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*restartRecoveryHarness, *runnerv1.HeartbeatAcknowledgement)
	}{
		{name: "non HTTPS", mutate: func(_ *restartRecoveryHarness, ack *runnerv1.HeartbeatAcknowledgement) {
			ack.Reconciliations[0].CompleteLogUpload.Uri = "http://logs.example/log.gz?secret"
		}},
		{name: "unknown upload field", mutate: func(_ *restartRecoveryHarness, ack *runnerv1.HeartbeatAcknowledgement) {
			ack.Reconciliations[0].CompleteLogUpload.ProtoReflect().SetUnknown([]byte{0x20, 0x01})
		}},
		{name: "expired", mutate: func(_ *restartRecoveryHarness, ack *runnerv1.HeartbeatAcknowledgement) {
			ack.Reconciliations[0].CompleteLogUpload.ExpiresAt = timestamppb.New(now)
		}},
		{name: "upload expires with lease", mutate: func(_ *restartRecoveryHarness, ack *runnerv1.HeartbeatAcknowledgement) {
			ack.Reconciliations[0].CompleteLogUpload.ExpiresAt = ack.Reconciliations[0].Lease.ExpiresAt
		}},
		{name: "substituted lease expiry", mutate: func(_ *restartRecoveryHarness, ack *runnerv1.HeartbeatAcknowledgement) {
			ack.Reconciliations[0].Lease.ExpiresAt = timestamppb.New(now.Add(7 * time.Minute))
		}},
		{name: "expired lease", mutate: func(_ *restartRecoveryHarness, ack *runnerv1.HeartbeatAcknowledgement) {
			ack.Reconciliations[0].Lease.ExpiresAt = timestamppb.New(now)
		}},
		{name: "non active", mutate: func(_ *restartRecoveryHarness, ack *runnerv1.HeartbeatAcknowledgement) {
			ack.Reconciliations[0].Status = runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED
		}},
		{name: "substituted attempt", mutate: func(_ *restartRecoveryHarness, ack *runnerv1.HeartbeatAcknowledgement) {
			ack.Reconciliations[0].Attempt.AttemptId = "30000000-0000-0000-0000-000000000002"
		}},
		{name: "substituted runner", mutate: func(h *restartRecoveryHarness, _ *runnerv1.HeartbeatAcknowledgement) {
			h.session.authenticated.RunnerId = "50000000-0000-0000-0000-000000000002"
		}},
		{name: "not advertised on stream", mutate: func(h *restartRecoveryHarness, _ *runnerv1.HeartbeatAcknowledgement) {
			h.session.restartUploadRecovery = false
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			uploader := new(restartRecoveryUploader)
			harness := newRestartRecoveryHarness(t, now, uploader)
			heartbeat := harness.sendHeartbeat(t, now)
			ack := harness.heartbeatAcknowledgement(heartbeat, now, validCompleteLogUpload(now))
			test.mutate(harness, ack)
			if err := harness.session.handleHeartbeatAcknowledgement(ack, now); err == nil {
				t.Fatal("invalid recovery upload was accepted")
			}
			if uploader.calls != 0 || len(harness.client.journal.snapshot().PendingMessage) != 0 || harness.client.completeLogTarget(harness.offer.GetJob().GetLease(), harness.offer.GetJob().GetAttempt()) != nil {
				t.Fatalf("invalid recovery upload mutated terminal state: calls=%d", uploader.calls)
			}
		})
	}
}

func TestActiveExecutionAcceptsNegotiatedReconnectUploadWithoutFailingTheJob(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	uploader := new(restartRecoveryUploader)
	harness := newRestartRecoveryHarness(t, now, uploader)
	harness.client.recovering = false
	heartbeat := harness.sendHeartbeat(t, now)
	if err := harness.session.handleHeartbeatAcknowledgement(harness.heartbeatAcknowledgement(heartbeat, now, validCompleteLogUpload(now)), now); err != nil {
		t.Fatal(err)
	}
	if uploader.calls != 0 || len(harness.client.journal.snapshot().PendingMessage) != 0 ||
		harness.client.completeLogTarget(harness.offer.GetJob().GetLease(), harness.offer.GetJob().GetAttempt()) == nil {
		t.Fatal("negotiated reconnect upload disrupted the active execution")
	}
}

func TestRestartRecoveryRejectsSubstitutedUploadedObject(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	uploader := &restartRecoveryUploader{substitute: true}
	harness := newRestartRecoveryHarness(t, now, uploader)
	heartbeat := harness.sendHeartbeat(t, now)
	if err := harness.session.handleHeartbeatAcknowledgement(harness.heartbeatAcknowledgement(heartbeat, now, validCompleteLogUpload(now)), now); err == nil {
		t.Fatal("substituted uploaded object was accepted")
	}
	if uploader.calls != 1 || len(harness.client.journal.snapshot().PendingMessage) != 0 || harness.client.completeLogTarget(harness.offer.GetJob().GetLease(), harness.offer.GetJob().GetAttempt()) != nil {
		t.Fatalf("substituted object mutated terminal state: calls=%d", uploader.calls)
	}
}

func assertNoRestartUploadSecret(t *testing.T, root, secret string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("upload capability secret persisted in %s", filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
