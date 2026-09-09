package gatewayclient

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type recordingCompleteLogUploader struct {
	calls            int
	targetObjectKeys []string
	object           *runnerv1.LogObject
	err              error
}

func (u *recordingCompleteLogUploader) Upload(_ context.Context, target *completeLogTarget, log *execution.CompleteLog) (*runnerv1.LogObject, error) {
	u.calls++
	if target == nil || strings.Contains(target.objectKey, "?") || log == nil || log.Archive == nil {
		return nil, errors.New("invalid test upload")
	}
	u.targetObjectKeys = append(u.targetObjectKeys, target.objectKey)
	object := proto.Clone(u.object).(*runnerv1.LogObject)
	object.ObjectKey = target.objectKey
	return object, u.err
}

func TestRemoteTerminalResultsIncludeCompleteLogAndOmitUnavailableUsage(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		classification execution.Classification
		wantCompleted  bool
		wantOutcome    runnerv1.ResultOutcome
	}{
		{name: "passed", classification: execution.ClassificationPassed, wantCompleted: true, wantOutcome: runnerv1.ResultOutcome_RESULT_OUTCOME_PASSED},
		{name: "workload failure", classification: execution.ClassificationWorkloadFailure},
		{name: "infrastructure failure", classification: execution.ClassificationInfrastructureFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, offer := activeEvidenceClient(t, now)
			uploader := &recordingCompleteLogUploader{object: testLogObject()}
			client.logUploader = uploader
			var sent *runnerv1.RunnerMessage
			session := &clientSession{client: client, rootContext: context.Background(), send: func(message *runnerv1.RunnerMessage) error {
				sent = proto.Clone(message).(*runnerv1.RunnerMessage)
				return nil
			}}
			status := "failed"
			if test.classification == execution.ClassificationPassed {
				status = "passed"
			}
			log := testCompleteLog(t, []byte("remote evidence\n"))
			result := execution.Result{SchemaVersion: execution.ResultSchemaVersion, JobID: offer.GetJob().GetLease().GetJobId(), Status: status, Classification: test.classification, Phase: execution.PhaseCompleted, CompleteLog: log, StartedAt: now, CompletedAt: now}
			if test.classification != execution.ClassificationPassed {
				result.Failure = execution.NewFailure(test.classification, "execution_failed", "execution failed")
			}
			if err := session.handleWorkerEvent(workerEvent{result: &result}); err != nil {
				t.Fatal(err)
			}
			if uploader.calls != 1 || result.CompleteLog.Archive != nil {
				t.Fatalf("upload calls = %d archive = %#v", uploader.calls, result.CompleteLog.Archive)
			}
			var terminalLog *runnerv1.LogObject
			if test.wantCompleted {
				structured := sent.GetCompleted().GetResult()
				if structured == nil || structured.GetOutcome() != test.wantOutcome || structured.GetUsage() != nil || !proto.Equal(structured.GetCompleteLog(), testLogObject()) {
					t.Fatalf("completed result = %#v", structured)
				}
				terminalLog = structured.GetCompleteLog()
			} else {
				failed := sent.GetFailed()
				category := runnerv1.FailureCategory_FAILURE_CATEGORY_INFRASTRUCTURE
				if test.classification == execution.ClassificationWorkloadFailure {
					category = runnerv1.FailureCategory_FAILURE_CATEGORY_PLUGIN
				}
				if failed == nil || failed.GetUsage() != nil || !proto.Equal(failed.GetCompleteLog(), testLogObject()) || failed.GetFailure().GetCategory() != category {
					t.Fatalf("failed result = %#v", failed)
				}
				terminalLog = failed.GetCompleteLog()
			}
			gatewayKey := offer.GetJob().GetCompleteLogUpload().GetObjectKey()
			if len(uploader.targetObjectKeys) != 1 || uploader.targetObjectKeys[0] != gatewayKey || terminalLog.GetObjectKey() != gatewayKey || strings.Contains(offer.GetJob().GetCompleteLogUpload().GetUri(), gatewayKey) {
				t.Fatalf("session upload identity = gateway %q targets %q terminal %q", gatewayKey, uploader.targetObjectKeys, terminalLog.GetObjectKey())
			}
			encoded, err := proto.Marshal(sent)
			if err != nil || bytes.Contains(encoded, []byte("signature")) || bytes.Contains(encoded, []byte("logs.example")) {
				t.Fatalf("terminal message contains upload capability: %q, %v", encoded, err)
			}
		})
	}
}

func TestRemoteUploadFailureBecomesClassifiedInfrastructureFailure(t *testing.T) {
	for _, classification := range []execution.Classification{execution.ClassificationPassed, execution.ClassificationWorkloadFailure} {
		t.Run(string(classification), func(t *testing.T) {
			now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
			client, _ := activeEvidenceClient(t, now)
			uploader := &recordingCompleteLogUploader{object: testLogObject(), err: errors.New("request included secret? no")}
			client.logUploader = uploader
			var sent *runnerv1.RunnerMessage
			session := &clientSession{client: client, rootContext: context.Background(), send: func(message *runnerv1.RunnerMessage) error {
				sent = proto.Clone(message).(*runnerv1.RunnerMessage)
				return nil
			}}
			result := execution.Result{SchemaVersion: execution.ResultSchemaVersion, Status: "passed", Classification: execution.ClassificationPassed, Phase: execution.PhaseCompleted, CompleteLog: testCompleteLog(t, []byte("remote evidence\n")), StartedAt: now, CompletedAt: now}
			if classification == execution.ClassificationWorkloadFailure {
				result.Status = "failed"
				result.Classification = classification
				result.Failure = execution.NewFailure(classification, "on_enable_failure", "probe observed a plugin lifecycle exception")
				result.Failure.Stage = execution.FailureStageStartup
			}
			if err := session.handleWorkerEvent(workerEvent{result: &result}); err != nil {
				t.Fatal(err)
			}
			failed := sent.GetFailed()
			if uploader.calls != 1 || failed == nil || failed.GetFailure().GetCode() != "complete_log_upload_failed" || failed.GetFailure().GetStage() != runnerv1.FailureStage_FAILURE_STAGE_RESULT_UPLOAD || failed.GetFailure().GetCategory() != runnerv1.FailureCategory_FAILURE_CATEGORY_INFRASTRUCTURE || !failed.GetFailure().GetRetryable() || failed.GetUsage() != nil || failed.GetCompleteLog() != nil {
				t.Fatalf("upload failure = %#v calls=%d", failed, uploader.calls)
			}
			if strings.Contains(failed.GetFailure().GetSummary(), "secret") {
				t.Fatalf("upload failure leaked underlying error: %#v", failed.GetFailure())
			}
		})
	}
}

func TestRemoteTerminalResultsCarryMeasuredUsageForEveryCompletedOrFailedOutcome(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 123456789, time.FixedZone("fixture", 90*60))
	completedAt := now.Add(2*time.Second + 765432*time.Nanosecond)
	tests := []struct {
		name           string
		classification execution.Classification
		completed      bool
	}{
		{name: "passed", classification: execution.ClassificationPassed, completed: true},
		{name: "workload failure", classification: execution.ClassificationWorkloadFailure},
		{name: "infrastructure failure", classification: execution.ClassificationInfrastructureFailure},
		{name: "timeout", classification: execution.ClassificationTimedOut},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, offer := activeEvidenceClient(t, now)
			client.clearCompleteLogTarget()
			var sent *runnerv1.RunnerMessage
			session := &clientSession{client: client, rootContext: context.Background(), send: func(message *runnerv1.RunnerMessage) error {
				sent = proto.Clone(message).(*runnerv1.RunnerMessage)
				return nil
			}}
			measured := execution.ResourceUsage{CPUTime: 4 * time.Second, PeakMemoryBytes: 2048, DiskReadBytes: 10, DiskWriteBytes: 20}
			status := "failed"
			if test.classification == execution.ClassificationPassed {
				status = "passed"
			}
			result := execution.Result{SchemaVersion: execution.ResultSchemaVersion, JobID: offer.GetJob().GetLease().GetJobId(), Status: status, Classification: test.classification, Phase: execution.PhaseCompleted, StartedAt: now, CompletedAt: completedAt, Usage: execution.UsageResult{MeasuredResources: &measured}}
			if test.classification != execution.ClassificationPassed {
				result.Failure = execution.NewFailure(test.classification, "execution_failed", "execution failed")
			}
			if err := session.handleWorkerEvent(workerEvent{result: &result}); err != nil {
				t.Fatal(err)
			}
			var usage *runnerv1.ResourceUsage
			if test.completed {
				usage = sent.GetCompleted().GetResult().GetUsage()
				terminal := sent.GetCompleted().GetResult()
				if terminal.GetStartedAt().AsTime() != now.UTC().Truncate(time.Microsecond) || terminal.GetCompletedAt().AsTime() != completedAt.UTC().Truncate(time.Microsecond) || terminal.GetCompletedAt().AsTime().Sub(terminal.GetStartedAt().AsTime()) != completedAt.UTC().Truncate(time.Microsecond).Sub(now.UTC().Truncate(time.Microsecond)) {
					t.Fatalf("normalized completed timestamps = %s .. %s", terminal.GetStartedAt().AsTime(), terminal.GetCompletedAt().AsTime())
				}
			} else {
				usage = sent.GetFailed().GetUsage()
				if sent.GetFailed().GetFailedAt().AsTime() != completedAt.UTC().Truncate(time.Microsecond) {
					t.Fatalf("normalized failed timestamp = %s", sent.GetFailed().GetFailedAt().AsTime())
				}
			}
			if usage.GetCpuTime().AsDuration() != 4*time.Second || usage.GetPeakMemoryBytes() != 2048 || usage.GetDiskReadBytes() != 10 || usage.GetDiskWriteBytes() != 20 {
				t.Fatalf("terminal usage = %#v", usage)
			}
		})
	}
}

func TestTerminalTimestampNormalizationRejectsNegativeDuration(t *testing.T) {
	started := time.Date(2026, 8, 31, 12, 0, 1, 999999999, time.UTC)
	if _, _, err := normalizedTerminalTimes(started, started.Add(-time.Nanosecond)); err == nil {
		t.Fatal("negative normalized terminal duration was accepted")
	}
}

func TestRemoteTerminalReplayDoesNotReuploadOrReexecute(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client, _ := activeEvidenceClient(t, now)
	uploader := &recordingCompleteLogUploader{object: testLogObject()}
	client.logUploader = uploader
	session := &clientSession{client: client, rootContext: context.Background(), send: func(*runnerv1.RunnerMessage) error { return errors.New("disconnected") }}
	result := execution.Result{SchemaVersion: execution.ResultSchemaVersion, Status: "passed", Classification: execution.ClassificationPassed, Phase: execution.PhaseCompleted, CompleteLog: testCompleteLog(t, []byte("remote evidence\n")), StartedAt: now, CompletedAt: now}
	if err := session.handleWorkerEvent(workerEvent{result: &result}); err == nil {
		t.Fatal("handleWorkerEvent() error = nil")
	}
	if uploader.calls != 1 || len(client.journal.snapshot().PendingMessage) == 0 || result.CompleteLog.Archive != nil {
		t.Fatalf("durable terminal state = calls %d state %#v archive %#v", uploader.calls, client.journal.snapshot(), result.CompleteLog.Archive)
	}
	var replayed *runnerv1.RunnerMessage
	reconnected := &clientSession{client: client, send: func(message *runnerv1.RunnerMessage) error {
		replayed = proto.Clone(message).(*runnerv1.RunnerMessage)
		return nil
	}}
	if err := reconnected.replayPending(); err != nil {
		t.Fatal(err)
	}
	if uploader.calls != 1 || replayed.GetCompleted() == nil {
		t.Fatalf("replay = %#v calls=%d", replayed, uploader.calls)
	}
}

func TestOfferUploadCapabilityIsKeptOutOfJournalAndWorkerSpecification(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	config := validConfig()
	config.Resources = validOfferConfig().Resources
	client := newClient(config, nil)
	client.worker = &gatedWorker{preparing: make(chan struct{}), executed: make(chan struct{}), now: now}
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	offer.Job.CompleteLogUpload = validCompleteLogUpload(now)
	var sent *runnerv1.RunnerMessage
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	session := &clientSession{client: client, authenticated: authenticated, objectUploadIdentity: true, send: func(message *runnerv1.RunnerMessage) error {
		sent = proto.Clone(message).(*runnerv1.RunnerMessage)
		return nil
	}}
	envelope := uniqueGatewayMessage(now, "offer-with-upload", &runnerv1.GatewayMessage_Offer{Offer: offer})
	if err := session.handleOffer(envelope, now); err != nil {
		t.Fatal(err)
	}
	state := client.journal.snapshot()
	if sent.GetLeaseAccepted() == nil || state.Active == nil {
		t.Fatalf("offer was not accepted: %#v %#v", sent, state)
	}
	if bytes.Contains(state.Active.Specification, []byte("signature=secret")) || bytes.Contains(state.PendingMessage, []byte("signature=secret")) {
		t.Fatal("journal contains presigned upload capability")
	}
	specification := new(runnerv1.JobSpecification)
	if err := proto.Unmarshal(state.Active.Specification, specification); err != nil {
		t.Fatal(err)
	}
	target := client.completeLogTarget(offer.GetJob().GetLease(), offer.GetJob().GetAttempt())
	if specification.GetCompleteLogUpload() != nil || target == nil || target.objectKey != offer.GetJob().GetCompleteLogUpload().GetObjectKey() || strings.Contains(target.uri, target.objectKey) {
		t.Fatalf("sanitized specification = %#v target = %#v", specification.GetCompleteLogUpload(), target)
	}
}

func activeEvidenceClient(t *testing.T, now time.Time) (*Client, *runnerv1.LeaseOffer) {
	t.Helper()
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	offer := validLeaseOffer(now)
	offer.Job.CompleteLogUpload = validCompleteLogUpload(now)
	sanitized := proto.Clone(offer.GetJob()).(*runnerv1.JobSpecification)
	sanitized.CompleteLogUpload = nil
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(sanitized)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer", OfferDigest: bytes.Repeat([]byte{1}, 32), Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	target, rejection := validateCompleteLogUpload(offer.GetJob().GetCompleteLogUpload(), now, offer.GetOfferExpiresAt().AsTime(), offer.GetJob().GetLease().GetExpiresAt().AsTime(), true)
	if rejection != nil {
		t.Fatal(rejection)
	}
	client.setCompleteLogTarget(offer.GetJob(), target)
	return client, offer
}

func testLogObject() *runnerv1.LogObject {
	return &runnerv1.LogObject{ObjectKey: "staging/execution/attempt/log.gz", Digest: &runnerv1.Digest{Algorithm: runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: bytes.Repeat([]byte{2}, 32)}, CompressedSizeBytes: 123, ContentType: completeLogUploadContentType}
}

func TestRemoteEarlyFailureWithoutArchivePreservesOriginalFailure(t *testing.T) {
	for _, phase := range []execution.Phase{execution.PhaseValidation, execution.PhaseResolution, execution.PhasePreparation} {
		t.Run(string(phase), func(t *testing.T) {
			now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
			client, offer := activeEvidenceClient(t, now)
			uploader := &recordingCompleteLogUploader{object: testLogObject()}
			client.logUploader = uploader
			var sent *runnerv1.RunnerMessage
			session := &clientSession{client: client, rootContext: context.Background(), send: func(message *runnerv1.RunnerMessage) error {
				sent = proto.Clone(message).(*runnerv1.RunnerMessage)
				return nil
			}}
			result := execution.FailedResult(offer.GetJob().GetLease().GetJobId(), phase, execution.ClassificationInvalidJob, "remote_job_adaptation_failed", errors.New("unsupported environment"))
			expected := resultFailure(result)
			if err := session.handleWorkerEvent(workerEvent{result: &result}); err != nil {
				t.Fatal(err)
			}
			failed := sent.GetFailed()
			if uploader.calls != 0 || failed == nil || !proto.Equal(failed.GetFailure(), expected) || failed.GetCompleteLog() != nil || sent.GetCompleted() != nil {
				t.Fatal("original pre-execution failure was masked or uploaded")
			}
		})
	}
}

func TestRemoteMissingArchiveStillRefusesSuccessAndPostExecutionFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		phase    execution.Phase
		passed   bool
		executed bool
		partial  bool
	}{
		{name: "success", phase: execution.PhaseCompleted, passed: true},
		{name: "success-early-phase", phase: execution.PhaseValidation, passed: true},
		{name: "executed", phase: execution.PhaseExecution},
		{name: "collection", phase: execution.PhaseCollection},
		{name: "execution-present", phase: execution.PhasePreparation, executed: true},
		{name: "partial-archive", phase: execution.PhasePreparation, partial: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
			client, offer := activeEvidenceClient(t, now)
			uploader := &recordingCompleteLogUploader{object: testLogObject()}
			client.logUploader = uploader
			var sent *runnerv1.RunnerMessage
			session := &clientSession{client: client, rootContext: context.Background(), send: func(message *runnerv1.RunnerMessage) error {
				sent = proto.Clone(message).(*runnerv1.RunnerMessage)
				return nil
			}}
			result := execution.FailedResult(offer.GetJob().GetLease().GetJobId(), test.phase, execution.ClassificationInfrastructureFailure, "execution_failed", errors.New("execution failed"))
			if test.passed {
				result.Status = "passed"
				result.Classification = execution.ClassificationPassed
				result.Failure = nil
			}
			if test.executed {
				result.Execution = &execution.ExecutionResult{}
			}
			if test.partial {
				result.CompleteLog = &execution.CompleteLog{}
			}
			if err := session.handleWorkerEvent(workerEvent{result: &result}); err != nil {
				t.Fatal(err)
			}
			if uploader.calls != 1 || sent.GetCompleted() != nil || sent.GetFailed().GetFailure().GetCode() != "complete_log_upload_failed" {
				t.Fatal("required missing log did not fail closed")
			}
		})
	}
}
