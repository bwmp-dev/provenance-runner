package gatewayclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRestartEvidenceSurvivesProcessReopenWithExactLogAndMonotonicUsage(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	journalPath, active, offer := restartEvidenceFixture(t, now)
	store, err := createRestartEvidenceStore(journalPath, offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
	if err != nil {
		t.Fatal(err)
	}
	store.observeLog(execution.LiveLogEntry{Stream: "stderr", Data: []byte("safe error")})
	store.observeLog(execution.LiveLogEntry{Stream: "stdout", Data: []byte("safe line\n"), Redacted: true})
	store.observeUsage(execution.ResourceUsage{CPUTime: 3 * time.Second, PeakMemoryBytes: 4096, DiskReadBytes: 20, DiskWriteBytes: 8})
	store.observeUsage(execution.ResourceUsage{CPUTime: time.Second, PeakMemoryBytes: 1024, DiskReadBytes: 30, DiskWriteBytes: 4, NetworkReceiveBytes: 7})
	if err := store.close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := openRestartEvidenceStore(journalPath, active)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.close() })
	recovered, err := reopened.snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeCompleteLog(recovered.CompleteLog) })
	if got := readRestartCompleteLog(t, recovered.CompleteLog); got != "[stdout]\nsafe line\n[stderr]\nsafe error\n" {
		t.Fatalf("complete log = %q", got)
	}
	usage := recovered.Usage
	if usage.GetCpuTime().AsDuration() != 3*time.Second || usage.GetPeakMemoryBytes() != 4096 || usage.GetDiskReadBytes() != 30 || usage.GetDiskWriteBytes() != 8 || usage.GetNetworkReceiveBytes() != 7 {
		t.Fatalf("cumulative usage = %#v", usage)
	}
	expectedIdentity, err := newRestartEvidenceIdentity(offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
	if err != nil || recovered.Identity != expectedIdentity {
		t.Fatalf("recovered identity = %#v, %v", recovered.Identity, err)
	}
	for _, name := range []string{"metadata.json", "stdout", "stderr"} {
		info, err := os.Stat(filepath.Join(restartEvidencePath(journalPath), name))
		if err != nil || info.Mode().Perm() != restartEvidenceFileMode {
			t.Fatalf("%s mode = %v, %v", name, info.Mode(), err)
		}
	}
	info, err := os.Stat(restartEvidencePath(journalPath))
	if err != nil || info.Mode().Perm() != restartEvidenceDirectoryMode {
		t.Fatalf("evidence directory mode = %v, %v", info.Mode(), err)
	}
}

func TestRestartEvidenceRecoveryDiscardsOnlyUncommittedSourceSuffix(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	journalPath, active, offer := restartEvidenceFixture(t, now)
	store, err := createRestartEvidenceStore(journalPath, offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
	if err != nil {
		t.Fatal(err)
	}
	store.observeLog(execution.LiveLogEntry{Stream: "stdout", Data: []byte("committed\n")})
	store.observeUsage(execution.ResourceUsage{CPUTime: time.Second})
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	stdoutPath := filepath.Join(restartEvidencePath(journalPath), "stdout")
	file, err := os.OpenFile(stdoutPath, os.O_WRONLY|os.O_APPEND, restartEvidenceFileMode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("uncommitted suffix\n")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := openRestartEvidenceStore(journalPath, active)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.close() })
	recovered, err := reopened.snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeCompleteLog(recovered.CompleteLog) })
	if got := readRestartCompleteLog(t, recovered.CompleteLog); got != "[stdout]\ncommitted\n" {
		t.Fatalf("recovered complete log = %q", got)
	}
	if info, err := os.Stat(stdoutPath); err != nil || info.Size() != int64(len("committed\n")) {
		t.Fatalf("recovered source size = %v, %v", info, err)
	}
}

func TestLiveExecutionObserverFeedsDurableRestartEvidence(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	journalPath, _, offer := restartEvidenceFixture(t, now)
	store, err := createRestartEvidenceStore(journalPath, offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
	if err != nil {
		t.Fatal(err)
	}
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	client.restartEvidence = store
	observer := newLiveExecutionObserver(client, offer.GetJob())
	observer.ObserveLog(execution.LiveLogEntry{Stream: "stdout", Data: []byte("observer output\n"), Redacted: true})
	observer.ObserveUsage(execution.ResourceUsage{CPUTime: 2 * time.Second, PeakMemoryBytes: 512})
	recovered, err := store.snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCompleteLog(recovered.CompleteLog)
		_ = client.Close()
	})
	if got := readRestartCompleteLog(t, recovered.CompleteLog); got != "[stdout]\nobserver output\n" {
		t.Fatalf("observer complete log = %q", got)
	}
	if recovered.Usage.GetCpuTime().AsDuration() != 2*time.Second || recovered.Usage.GetPeakMemoryBytes() != 512 {
		t.Fatalf("observer cumulative usage = %#v", recovered.Usage)
	}
}

func TestRestartEvidenceRejectsMissingCorruptSubstitutedAndUnsafeState(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*testing.T, string, *journalJob, *runnerv1.LeaseOffer)
	}{
		{name: "missing metadata", mutate: func(t *testing.T, directory string, _ *journalJob, _ *runnerv1.LeaseOffer) {
			if err := os.Remove(filepath.Join(directory, "metadata.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "corrupt source", mutate: func(t *testing.T, directory string, _ *journalJob, _ *runnerv1.LeaseOffer) {
			if err := os.WriteFile(filepath.Join(directory, "stdout"), []byte("substituted\n"), restartEvidenceFileMode); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong attempt", mutate: func(t *testing.T, _ string, active *journalJob, offer *runnerv1.LeaseOffer) {
			specification := new(runnerv1.JobSpecification)
			if err := proto.Unmarshal(active.Specification, specification); err != nil {
				t.Fatal(err)
			}
			specification.Attempt.AttemptId = "90000000-0000-0000-0000-000000000099"
			encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(specification)
			if err != nil {
				t.Fatal(err)
			}
			active.Specification = encoded
			offer.Job.Attempt = specification.Attempt
		}},
		{name: "unsafe permission", mutate: func(t *testing.T, directory string, _ *journalJob, _ *runnerv1.LeaseOffer) {
			if err := os.Chmod(filepath.Join(directory, "stdout"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unexpected entry", mutate: func(t *testing.T, directory string, _ *journalJob, _ *runnerv1.LeaseOffer) {
			if err := os.WriteFile(filepath.Join(directory, "unexpected"), nil, restartEvidenceFileMode); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			journalPath, active, offer := restartEvidenceFixture(t, now)
			store, err := createRestartEvidenceStore(journalPath, offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
			if err != nil {
				t.Fatal(err)
			}
			store.observeLog(execution.LiveLogEntry{Stream: "stdout", Data: []byte("original\n")})
			store.observeUsage(execution.ResourceUsage{CPUTime: time.Second})
			if err := store.close(); err != nil {
				t.Fatal(err)
			}
			directory := restartEvidencePath(journalPath)
			test.mutate(t, directory, active, offer)
			if _, err := openRestartEvidenceStore(journalPath, active); err == nil {
				t.Fatal("unsafe restart evidence was accepted")
			}
		})
	}
}

func TestRestartEvidenceFailsClosedOnMissingUsageAndCompleteLogBound(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	journalPath, active, offer := restartEvidenceFixture(t, now)
	store, err := createRestartEvidenceStore(journalPath, offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
	if err != nil {
		t.Fatal(err)
	}
	store.observeLog(execution.LiveLogEntry{Stream: "stdout", Data: []byte("log\n")})
	if _, err := store.snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("snapshot without usage error = %v", err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}

	metadata := restartEvidenceMetadata{StdoutBytes: evidence.MaximumCompleteLogBytes - int64(len("[stdout]\n")), StdoutLast: '\n'}
	if restartEvidenceWithinBound(metadata, "stdout", []byte("x")) {
		t.Fatal("oversized complete log was accepted")
	}
	reopened, err := openRestartEvidenceStore(journalPath, active)
	if err != nil {
		t.Fatalf("valid persisted source did not reopen after missing-usage snapshot: %v", err)
	}
	if err := reopened.close(); err != nil {
		t.Fatal(err)
	}
}

func TestRestartEvidenceObservationIsDurableBeforeReturn(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	journalPath, _, offer := restartEvidenceFixture(t, now)
	store, err := createRestartEvidenceStore(journalPath, offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
	if err != nil {
		t.Fatal(err)
	}
	store.observeLog(execution.LiveLogEntry{Stream: "stdout", Data: []byte("committed before return\n")})
	store.observeUsage(execution.ResourceUsage{CPUTime: 3 * time.Second, PeakMemoryBytes: 1024})

	// Reopen the files directly without flushing or closing the active writer. A
	// process killed immediately after either observation returns must expose the
	// same committed prefix and cumulative usage to restart recovery.
	recovered, err := loadRestartEvidenceStore(restartEvidencePath(journalPath), offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
	if err != nil {
		t.Fatal(err)
	}
	if recovered.metadata.StdoutBytes != int64(len("committed before return\n")) || recovered.metadata.Usage.CPUTime != 3*time.Second || !recovered.metadata.UsageObserved {
		t.Fatalf("durable observation = %#v", recovered.metadata)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
}

func TestRestartEvidenceAppendRejectsHardLinkedSource(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	journalPath, _, offer := restartEvidenceFixture(t, now)
	store, err := createRestartEvidenceStore(journalPath, offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	if err := os.Link(store.stdoutPath, filepath.Join(t.TempDir(), "stdout-hardlink")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	if privateFileMetadata(info) {
		t.Skip("platform does not expose private file ownership and link metadata")
	}
	store.observeLog(execution.LiveLogEntry{Stream: "stdout", Data: []byte("must not append\n")})
	if err := store.flush(); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("hard-linked restart evidence append error = %v", err)
	}
}

func TestRestartEvidenceContainsNoOfferOrCredentialSecretAndCleansIdempotently(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	config := validConfig()
	config.Resources = validOfferConfig().Resources
	config.journalFile = filepath.Join(t.TempDir(), "journal.json")
	config.credential = []byte("runner-credential-secret")
	client := newClient(config, nil)
	client.worker = &gatedWorker{preparing: make(chan struct{}), executed: make(chan struct{}), now: now}
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	offer.Job.CompleteLogUpload = validCompleteLogUpload(now)
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	var sent *runnerv1.RunnerMessage
	session := &clientSession{client: client, authenticated: authenticated, send: func(message *runnerv1.RunnerMessage) error {
		sent = proto.Clone(message).(*runnerv1.RunnerMessage)
		return nil
	}}
	if err := session.handleOffer(uniqueGatewayMessage(now, "offer-secret-test", &runnerv1.GatewayMessage_Offer{Offer: offer}), now); err != nil {
		t.Fatal(err)
	}
	if sent.GetLeaseAccepted() == nil {
		t.Fatalf("offer not accepted: %#v", sent.GetLeaseRejected())
	}
	store := client.activeRestartEvidence()
	store.observeLog(execution.LiveLogEntry{Stream: "stdout", Data: []byte("redacted output\n"), Redacted: true})
	store.observeUsage(execution.ResourceUsage{CPUTime: time.Second})
	if err := store.flush(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{config.journalFile, filepath.Join(store.directory, "metadata.json"), filepath.Join(store.directory, "stdout"), filepath.Join(store.directory, "stderr")} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("signature=secret")) || bytes.Contains(data, config.credential) || bytes.Contains(data, []byte("logs.example")) {
			t.Fatalf("secret persisted in %s", path)
		}
	}
	if err := client.journal.update(func(state *journalState) error {
		state.PendingMessage = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	lease := proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity)
	attempt := proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity)
	failed := &runnerv1.JobFailed{Lease: lease, Attempt: attempt, FailedAt: timestamppb.New(now), Failure: &runnerv1.FailureDetail{
		Category: runnerv1.FailureCategory_FAILURE_CATEGORY_INFRASTRUCTURE, Stage: runnerv1.FailureStage_FAILURE_STAGE_EXECUTION,
		Code: "runner_restarted", Summary: "restart", Retryable: true,
	}}
	if err := session.queueDurable(&runnerv1.RunnerMessage_Failed{Failed: failed}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.directory); err != nil {
		t.Fatalf("evidence removed before terminal acknowledgement: %v", err)
	}
	acknowledgement := &runnerv1.RunnerEventAcknowledgement{
		RunnerMessageId: sent.GetMessageId(), CommittedAt: timestamppb.New(now), Reconciliation: &runnerv1.LeaseReconciliation{
			Lease: lease, Attempt: attempt, Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED,
			Status: runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, TerminalMessageId: sent.GetMessageId(),
		},
	}
	if err := session.handleEventAcknowledgement(acknowledgement, now); err != nil {
		t.Fatal(err)
	}
	if err := client.clearRestartEvidence(); err != nil {
		t.Fatalf("idempotent cleanup = %v", err)
	}
	if _, err := os.Lstat(restartEvidencePath(config.journalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restart evidence directory survived cleanup: %v", err)
	}
}

func TestRecoveredDurableEvidenceDefersIncompleteRestartFailure(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	config := validConfig()
	config.journalFile = filepath.Join(t.TempDir(), "journal.json")
	journal, err := openJournal(config.journalFile)
	if err != nil {
		t.Fatal(err)
	}
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, 32), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	store, err := createRestartEvidenceStore(config.journalFile, offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
	if err != nil {
		t.Fatal(err)
	}
	store.observeLog(execution.LiveLogEntry{Stream: "stdout", Data: []byte("before restart\n")})
	store.observeUsage(execution.ResourceUsage{CPUTime: time.Second})
	if err := store.close(); err != nil {
		t.Fatal(err)
	}

	client, err := newClientWithWorker(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.now = func() time.Time { return now }
	var sent []*runnerv1.RunnerMessage
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	session := &clientSession{client: client, authenticated: authenticated, rootContext: context.Background(), send: func(message *runnerv1.RunnerMessage) error {
		sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}}
	if err := session.sendHeartbeat(now); err != nil {
		t.Fatal(err)
	}
	heartbeat := session.pendingHeartbeat
	acknowledgement := &runnerv1.HeartbeatAcknowledgement{
		RunnerMessageId: heartbeat.GetMessageId(), Sequence: heartbeat.GetHeartbeat().GetSequence(), CommittedAt: timestamppb.New(now),
		Reconciliations: []*runnerv1.LeaseReconciliation{{
			Lease: proto.Clone(offer.GetJob().GetLease()).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(offer.GetJob().GetAttempt()).(*runnerv1.AttemptIdentity),
			Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED, Status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING,
		}},
	}
	if err := session.handleHeartbeatAcknowledgement(acknowledgement, now); err != nil {
		t.Fatal(err)
	}
	state := client.journal.snapshot()
	if len(sent) != 1 || len(state.PendingMessage) != 0 || state.Active == nil {
		t.Fatalf("recovery emitted incomplete terminal event: sent=%d state=%#v", len(sent), state)
	}
	if _, err := client.activeRestartEvidence().snapshot(context.Background()); err != nil {
		t.Fatalf("durable evidence was not retained: %v", err)
	}
}

func restartEvidenceFixture(t *testing.T, now time.Time) (string, *journalJob, *runnerv1.LeaseOffer) {
	t.Helper()
	journalPath := filepath.Join(t.TempDir(), "journal.json")
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	active := &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, 32), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
	return journalPath, active, offer
}

func readRestartCompleteLog(t *testing.T, completeLog *execution.CompleteLog) string {
	t.Helper()
	reader, err := gzip.NewReader(io.NewSectionReader(completeLog.Archive, 0, completeLog.CompressedBytes))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
