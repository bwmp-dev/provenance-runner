package gatewayclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestTerminalEvidenceDurableReopenReplayAndDowngrade(t *testing.T) {
	for _, passed := range []bool{true, false} {
		t.Run(map[bool]string{true: "completed", false: "failed"}[passed], func(t *testing.T) {
			now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
			client, offer := activeEvidenceClient(t, now)
			raw, err := os.ReadFile("../terminalevidence/testdata/platform-created-job.json")
			if err != nil {
				t.Fatal(err)
			}
			job := new(runnerv1.JobSpecification)
			if err := protojson.Unmarshal(raw, job); err != nil {
				t.Fatal(err)
			}
			job.Lease = offer.Job.Lease
			job.Attempt = offer.Job.Attempt
			job.JobCorrelation = nil
			if !passed {
				job.TargetPluginName = "SuccessFixture"
			}
			contextEvidence, err := terminalevidence.NewContext(job)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := proto.Marshal(job)
			if err != nil {
				t.Fatal(err)
			}
			client.journal.path = filepath.Join(t.TempDir(), "journal.json")
			if err := client.journal.update(func(s *journalState) error { s.Active.Specification = encoded; return nil }); err != nil {
				t.Fatal(err)
			}
			uploader := &recordingCompleteLogUploader{object: testLogObject()}
			client.logUploader = uploader
			result := execution.Result{StartedAt: now, CompletedAt: now.Add(time.Second), TerminalContext: contextEvidence, TerminalObservations: []terminalevidence.Observation{{Type: "plugin-enabled", Name: job.TargetPluginName, Loaded: true, Enabled: passed}}, CompleteLog: testCompleteLog(t, []byte("safe complete log\n"))}
			if !passed {
				// This exact projection is mutation-checked against actual Paper
				// Collect -> Executor output in provider_test.go. Only the target
				// materialization name is selected for this synthetic dispatch.
				observationBytes, err := os.ReadFile("testdata/paper-terminal-observations.json")
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(observationBytes, &result.TerminalObservations); err != nil {
					t.Fatal(err)
				}
				result.Classification = execution.ClassificationWorkloadFailure
				result.Failure = execution.NewFailure(execution.ClassificationWorkloadFailure, "on_enable_failure", "plugin startup failed")
				result.Failure.Stage = execution.FailureStageStartup
			} else {
				result.Classification = execution.ClassificationPassed
			}
			var sent *runnerv1.RunnerMessage
			session := &clientSession{client: client, rootContext: context.Background(), authenticated: authenticatedMessage(now, nil).GetAuthenticated(), terminalEvidenceV1: true, send: func(m *runnerv1.RunnerMessage) error {
				sent = proto.Clone(m).(*runnerv1.RunnerMessage)
				return errors.New("disconnected")
			}}
			if err := session.queueResult(result); err == nil {
				t.Fatal("expected disconnect")
			}
			if sent == nil || terminalProof(sent) == nil {
				t.Fatal("production queue omitted evidence")
			}
			if (sent.GetCompleted() != nil) != passed {
				t.Fatal("terminal outcome changed")
			}
			if err := terminalevidence.ValidateFrozen(terminalProof(sent), job, testRunnerID); err != nil {
				t.Fatal(err)
			}
			original := client.journal.snapshot().PendingMessage
			reopened, err := openJournal(client.journal.path)
			if err != nil {
				t.Fatal(err)
			}
			client.journal = reopened
			calls := 0
			session.send = func(m *runnerv1.RunnerMessage) error {
				calls++
				if !proto.Equal(m, sent) {
					t.Fatal("replay changed proof/message")
				}
				return nil
			}
			session.terminalEvidenceV1 = false
			if err := session.replayPending(); err == nil || calls != 0 {
				t.Fatal("downgrade sent or stripped queued evidence")
			}
			if !bytes.Equal(original, client.journal.snapshot().PendingMessage) {
				t.Fatal("downgrade mutated durable bytes")
			}
			session.terminalEvidenceV1 = true
			if err := session.replayPending(); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || uploader.calls != 1 {
				t.Fatal("replay did not send exactly once without upload")
			}
			ack := eventAcknowledgement(now.Add(2*time.Second), "proof-ack", sent, runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED, runnerv1.JobPhase_JOB_PHASE_RUNNING).GetEventAcknowledgement()
			bad := proto.Clone(ack).(*runnerv1.RunnerEventAcknowledgement)
			bad.Reconciliation.Attempt.AttemptId = "wrong"
			if session.handleEventAcknowledgement(bad, now.Add(2*time.Second)) == nil {
				t.Fatal("foreign acknowledgement accepted")
			}
			if err := session.handleEventAcknowledgement(ack, now.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			if client.journal.snapshot().Active != nil || len(client.journal.snapshot().PendingMessage) != 0 {
				t.Fatal("ack did not clear durable proof")
			}
		})
	}
}

func TestTerminalEvidenceWholeMessageBoundAndLegacyAbsence(t *testing.T) {
	message := &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_Failed{Failed: &runnerv1.JobFailed{ExecutionEvidence: &runnerv1.ExecutionEvidence{CanonicalJson: []byte(`{}`)}, Failure: &runnerv1.FailureDetail{Summary: strings.Repeat("x", MaximumMessageBytes)}}}}
	if terminalMessageBound(message) == nil {
		t.Fatal("oversized proof-bearing message accepted")
	}
	if _, err := (strictProtocolCodec{}).Marshal(message); err == nil {
		t.Fatal("codec bypassed proof message bound")
	}
	message.GetFailed().ExecutionEvidence = nil
	if err := validateTerminalProof(message, journalState{}, "runner"); err != nil {
		t.Fatal("legacy terminal absence rejected")
	}
	if terminalMessageBound(message) != nil {
		t.Fatal("new proof bound changed legacy validation")
	}
}
