package gatewayclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestUploadIdentityRollbackIsNotConnectSchema(t *testing.T) {
	config := validConfig()
	config.DisableObjectUploadIdentity = true
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("DisableObjectUploadIdentity")) || bytes.Contains(encoded, []byte("disableObjectUploadIdentity")) {
		t.Fatal("operator control leaked into connect schema")
	}
	decoded, err := decodeConfig(encoded)
	if err != nil || decoded.DisableObjectUploadIdentity {
		t.Fatalf("schema default changed: %v", err)
	}
	encoded = append(encoded[:len(encoded)-1], []byte(`,"disableObjectUploadIdentity":true}`)...)
	if _, err := decodeConfig(encoded); err == nil {
		t.Fatal("connect schema accepted operator-only control")
	}
}

type identityLogWorker struct {
	log *execution.CompleteLog
	now time.Time
}

func (w *identityLogWorker) Execute(ctx context.Context, _ *runnerv1.JobSpecification, before func(context.Context, execution.ExecutionStart) error) execution.Result {
	if err := before(ctx, execution.ExecutionStart{JobID: "job", Provider: "paper", EnvironmentIdentity: "paper"}); err != nil {
		return execution.FailedResult("job", execution.PhaseExecution, execution.ClassificationInfrastructureFailure, "before_execute_failed", err)
	}
	return execution.Result{SchemaVersion: execution.ResultSchemaVersion, JobID: "job", Status: "passed", Classification: execution.ClassificationPassed, Phase: execution.PhaseCompleted, CompleteLog: w.log, StartedAt: w.now, CompletedAt: w.now}
}

// These tests run the real authentication/capabilities/session loop. The
// transport records messages without rewriting capabilities or session flags.
func identitySession(t *testing.T, client *Client, now time.Time) (*scriptedStream, func()) {
	t.Helper()
	auth := authenticatedMessage(now, platformScope())
	auth.GetAuthenticated().LeaseDuration = durationpb.New(10 * time.Minute)
	stream := newScriptedStream(context.Background(), auth)
	client.connector = &scriptedConnector{results: []connectResult{{stream: stream}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() {
		established, err := client.runSession(ctx)
		if !established {
			err = errors.New("session did not authenticate")
		}
		done <- err
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
					t.Errorf("session ended: %v", err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("session did not stop")
			}
		})
	}
	t.Cleanup(stop)
	waitForSentMessages(t, stream, 3)
	stream.mu.Lock()
	first := proto.Clone(stream.sent[0]).(*runnerv1.RunnerMessage)
	capabilities := proto.Clone(stream.sent[1]).(*runnerv1.RunnerMessage)
	stream.mu.Unlock()
	if first.GetAuthenticate() == nil || capabilities.GetCapabilities() == nil {
		t.Fatal("authentication/capabilities ordering changed")
	}
	features := capabilities.GetCapabilities().GetFeatures()
	if validateAdvertisedFeatures(features) != nil || advertisedFeature(features, runnerv1.ProtocolFeature_PROTOCOL_FEATURE_OBJECT_UPLOAD_IDENTITY) == client.config.DisableObjectUploadIdentity {
		t.Fatalf("actual wire capabilities do not reflect operator policy: %v", features)
	}
	return stream, stop
}

func identityMessage(t *testing.T, stream *scriptedStream, match func(*runnerv1.RunnerMessage) bool) *runnerv1.RunnerMessage {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stream.mu.Lock()
		for _, message := range stream.sent {
			if match(message) {
				result := proto.Clone(message).(*runnerv1.RunnerMessage)
				stream.mu.Unlock()
				return result
			}
		}
		stream.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("expected session message was not sent")
	return nil
}

func TestRunSessionInitialUploadIdentityNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		disable, unexpectedKey bool
	}{
		{"negotiated", false, false}, {"legacy rollback", true, false}, {"reject unadvertised key", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			config := validConfig()
			config.Resources.CPUMillis = 2000
			config.DisableObjectUploadIdentity = tc.disable
			config.journalFile = filepath.Join(t.TempDir(), "journal.json")
			client, err := newClientWithWorker(config, nil, &identityLogWorker{log: testCompleteLog(t, []byte("session log\n")), now: now})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.now = func() time.Time { return now }
			uploader := &recordingCompleteLogUploader{object: testLogObject()}
			client.logUploader = uploader
			offer := validLeaseOffer(now)
			offer.Job.JobCorrelation = validJobCorrelation(offer)
			offer.Job.CompleteLogUpload = validCompleteLogUpload(now)
			upload := offer.Job.CompleteLogUpload
			wantKey := upload.ObjectKey
			if tc.disable && !tc.unexpectedKey {
				upload.ObjectKey = ""
				upload.Uri = "https://logs.example/legacy/session/log.gz?signature=private"
				wantKey = "legacy/session/log.gz"
			}
			stream, stop := identitySession(t, client, now)
			stream.receives <- receiveResult{message: uniqueGatewayMessage(now, "identity-offer", &runnerv1.GatewayMessage_Offer{Offer: offer})}
			message := identityMessage(t, stream, func(m *runnerv1.RunnerMessage) bool {
				return m.GetLeaseAccepted() != nil || m.GetLeaseRejected() != nil
			})
			if tc.unexpectedKey {
				stop()
				if message.GetLeaseRejected() == nil || !strings.Contains(message.GetLeaseRejected().GetSummary(), "invalid_complete_log_upload") || client.journal.snapshot().Active != nil {
					t.Fatal("unadvertised object key was accepted")
				}
				return
			}
			if message.GetLeaseAccepted() == nil {
				t.Fatalf("valid offer rejected: %v", message.GetLeaseRejected())
			}
			state := client.journal.snapshot()
			if bytes.Contains(state.Active.Specification, []byte(upload.Uri)) || bytes.Contains(state.Active.Specification, []byte(wantKey)) {
				t.Fatal("capability leaked into durable worker specification")
			}
			stream.receives <- receiveResult{message: eventAcknowledgement(now, "identity-accepted", message, runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED, runnerv1.JobPhase_JOB_PHASE_ACCEPTED)}
			preparing := identityMessage(t, stream, func(m *runnerv1.RunnerMessage) bool { return m.GetJobPreparing() != nil })
			stream.receives <- receiveResult{message: eventAcknowledgement(now, "identity-preparing", preparing, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_PREPARING)}
			started := identityMessage(t, stream, func(m *runnerv1.RunnerMessage) bool { return m.GetJobStarted() != nil })
			stream.receives <- receiveResult{message: eventAcknowledgement(now, "identity-started", started, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_RUNNING)}
			terminal := identityMessage(t, stream, func(m *runnerv1.RunnerMessage) bool { return m.GetCompleted() != nil || m.GetFailed() != nil })
			stop()
			if terminal.GetCompleted().GetResult().GetCompleteLog().GetObjectKey() != wantKey || uploader.calls != 1 || len(uploader.targetObjectKeys) != 1 || uploader.targetObjectKeys[0] != wantKey {
				t.Fatalf("session terminal identity incorrect: %v", terminal)
			}
			encoded, _ := proto.Marshal(terminal)
			if bytes.Contains(encoded, []byte("signature")) || bytes.Contains(encoded, []byte("logs.example")) {
				t.Fatal("terminal leaked URI")
			}
		})
	}
}

func TestRunSessionReconnectUploadIdentityNegotiation(t *testing.T) {
	for _, disable := range []bool{false, true} {
		name := "negotiated"
		if disable {
			name = "legacy rollback"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			uploader := new(restartRecoveryUploader)
			h := newRestartRecoveryHarness(t, now, uploader)
			h.client.config.DisableObjectUploadIdentity = disable
			first, stopFirst := identitySession(t, h.client, now)
			_ = identityMessage(t, first, func(m *runnerv1.RunnerMessage) bool { return m.GetHeartbeat() != nil })
			stopFirst() // transport lost before authoritative recovery response
			second, stopSecond := identitySession(t, h.client, now)
			heartbeat := identityMessage(t, second, func(m *runnerv1.RunnerMessage) bool { return m.GetHeartbeat() != nil })
			upload := validCompleteLogUpload(now)
			wantKey := upload.ObjectKey
			if disable {
				upload.ObjectKey = ""
				upload.Uri = "https://logs.example/legacy/reconnected/log.gz?signature=private"
				wantKey = "legacy/reconnected/log.gz"
			}
			ack := h.heartbeatAcknowledgement(heartbeat, now, upload)
			second.receives <- receiveResult{message: uniqueGatewayMessage(now, "identity-recovery", &runnerv1.GatewayMessage_HeartbeatAcknowledgement{HeartbeatAcknowledgement: ack})}
			terminal := identityMessage(t, second, func(m *runnerv1.RunnerMessage) bool { return m.GetFailed() != nil })
			stopSecond()
			if terminal.GetFailed().GetCompleteLog().GetObjectKey() != wantKey || uploader.calls != 1 {
				t.Fatalf("reconnected terminal identity = %v, uploads %d", terminal.GetFailed(), uploader.calls)
			}
			encoded, err := proto.Marshal(terminal)
			if err != nil || bytes.Contains(encoded, []byte("signature")) || bytes.Contains(encoded, []byte("logs.example")) {
				t.Fatal("terminal leaked upload URI")
			}
			assertNoRestartUploadSecret(t, filepath.Dir(h.client.config.journalFile), "signature=private")
		})
	}
}
