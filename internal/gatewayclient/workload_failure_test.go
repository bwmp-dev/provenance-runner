package gatewayclient

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// The input is checked against actual Paper provider/executor output by
// TestExecutorPreservesValidatedProbeFailureCode. Only clocks/lease identities
// and measured resources/log identity are fixed here for a portable wire fixture.
func TestPaperWorkloadFailureWireFixtureAndReplay(t *testing.T) {
	data, err := os.ReadFile("testdata/paper-workload-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var projection struct {
		Stage  execution.FailureStage
		Result execution.Result
	}
	if err := json.Unmarshal(data, &projection); err != nil {
		t.Fatal(err)
	}
	result := projection.Result
	result.Failure.Stage = projection.Stage
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	result.StartedAt, result.CompletedAt = now, now.Add(2*time.Second)
	result.Usage.MeasuredResources = &execution.ResourceUsage{CPUTime: time.Second, PeakMemoryBytes: 2048, DiskReadBytes: 10, DiskWriteBytes: 20}
	result.CompleteLog = testCompleteLog(t, []byte("remote evidence\n"))
	client, offer := activeEvidenceClient(t, now)
	uploader := &recordingCompleteLogUploader{object: testLogObject()}
	client.logUploader = uploader
	var original *runnerv1.RunnerMessage
	session := &clientSession{client: client, rootContext: context.Background(), send: func(m *runnerv1.RunnerMessage) error {
		original = proto.Clone(m).(*runnerv1.RunnerMessage)
		return errors.New("disconnected")
	}}
	if err := session.handleWorkerEvent(workerEvent{result: &result}); err == nil {
		t.Fatal("expected disconnect")
	}
	failed := original.GetFailed()
	if failed == nil || failed.Failure.Category != runnerv1.FailureCategory_FAILURE_CATEGORY_PLUGIN || failed.Failure.Stage != runnerv1.FailureStage_FAILURE_STAGE_STARTUP || failed.Failure.Code != "on_enable_failure" || failed.Failure.Retryable {
		t.Fatalf("lost classification: %v", original)
	}
	if !sameLeaseAttempt(failed.Lease, failed.Attempt, offer.Job.Lease, offer.Job.Attempt) || uploader.calls != 1 || result.CompleteLog.Archive != nil {
		t.Fatal("lost identity or log ownership")
	}
	expectedBytes, err := os.ReadFile("testdata/paper-workload-failed.json")
	if err != nil {
		t.Fatalf("missing fixture; actual: %s", protojson.Format(failed))
	}
	expected := new(runnerv1.JobFailed)
	if err := protojson.Unmarshal(expectedBytes, expected); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(expected, failed) {
		t.Fatalf("wire fixture differs: %s", protojson.Format(failed))
	}
	reconnect := &clientSession{client: client, send: func(m *runnerv1.RunnerMessage) error {
		if !proto.Equal(original, m) {
			t.Fatal("replay mutated terminal message")
		}
		return nil
	}}
	if err := reconnect.replayPending(); err != nil {
		t.Fatal(err)
	}
	if uploader.calls != 1 {
		t.Fatal("replay reuploaded complete log")
	}
	ack := eventAcknowledgement(now.Add(3*time.Second), "failed-ack", original, runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED, runnerv1.JobPhase_JOB_PHASE_RUNNING).GetEventAcknowledgement()
	bad := proto.Clone(ack).(*runnerv1.RunnerEventAcknowledgement)
	bad.Reconciliation.Attempt.AttemptId = "wrong-attempt"
	if err := reconnect.handleEventAcknowledgement(bad, now.Add(3*time.Second)); err == nil {
		t.Fatal("accepted substituted attempt")
	}
	if len(client.journal.snapshot().PendingMessage) == 0 {
		t.Fatal("bad ack removed pending evidence")
	}
	if err := reconnect.handleEventAcknowledgement(ack, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(client.journal.snapshot().PendingMessage) != 0 || client.journal.snapshot().Active != nil {
		t.Fatal("valid ack did not finish failed lease")
	}
}

func TestProviderFailureStagesAndLegacyFallback(t *testing.T) {
	for _, tc := range []struct {
		stage execution.FailureStage
		want  runnerv1.FailureStage
	}{
		{execution.FailureStagePreparation, runnerv1.FailureStage_FAILURE_STAGE_PREPARATION},
		{execution.FailureStageStartup, runnerv1.FailureStage_FAILURE_STAGE_STARTUP},
		{execution.FailureStageExecution, runnerv1.FailureStage_FAILURE_STAGE_EXECUTION},
		{"", runnerv1.FailureStage_FAILURE_STAGE_CLEANUP},
		{"hostile", runnerv1.FailureStage_FAILURE_STAGE_CLEANUP},
	} {
		t.Run(string(tc.stage), func(t *testing.T) {
			result := execution.Result{Classification: execution.ClassificationWorkloadFailure, Phase: execution.PhaseCollection, Failure: execution.NewFailure(execution.ClassificationWorkloadFailure, "unknown_code", "bounded failure")}
			result.Failure.Stage = tc.stage
			got := resultFailure(result)
			if got.Stage != tc.want || got.Code != "unknown_code" || got.Retryable {
				t.Fatalf("failure = %v", got)
			}
		})
	}
}
