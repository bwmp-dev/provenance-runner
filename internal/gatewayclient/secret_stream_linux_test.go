//go:build linux

package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type exchangeSandbox struct{}

func (exchangeSandbox) Identity() string              { return "synthetic" }
func (exchangeSandbox) SupportsTestSecretFiles() bool { return true }
func (exchangeSandbox) ResolveWorkload(context.Context, execution.Request, execution.IsolatedWorkload) (execution.Environment, error) {
	panic("not used")
}

type exchangeWorker struct {
	wait        bool
	failCleanup bool
	started     chan struct{}
	files       chan *testsecrets.Files
}

func (*exchangeWorker) SupportsTestSecretSource() bool { return true }
func (w *exchangeWorker) Execute(ctx context.Context, job *runnerv1.JobSpecification, before func(context.Context, execution.ExecutionStart) error) execution.Result {
	files, _, err := execution.AcquireTestSecretFiles(ctx, exchangeSandbox{})
	if err != nil || files == nil {
		return execution.FailedResult(job.Lease.JobId, execution.PhasePreparation, execution.ClassificationInfrastructureFailure, "synthetic_source_failed", errSecretDeliveryUnavailable)
	}
	defer files.Close()
	w.files <- files
	values, err := files.RedactionValues()
	if err != nil || len(values) != 1 || len(values[0]) != 65536 {
		return execution.FailedResult(job.Lease.JobId, execution.PhasePreparation, execution.ClassificationInfrastructureFailure, "synthetic_value_invalid", errSecretDeliveryUnavailable)
	}
	values[0] = ""
	if err := before(ctx, execution.ExecutionStart{}); err != nil {
		return execution.FailedResult(job.Lease.JobId, execution.PhaseExecution, execution.ClassificationInfrastructureFailure, "synthetic_start_failed", errSecretDeliveryUnavailable)
	}
	close(w.started)
	if w.wait {
		<-ctx.Done()
	}
	if w.failCleanup {
		result := execution.FailedResult(job.Lease.JobId, execution.PhaseExecution, execution.ClassificationInfrastructureFailure, "synthetic_cleanup_failed", errors.New("synthetic teardown failure"))
		result.Cleanup = &execution.CleanupResult{Attempted: true, Succeeded: false, Error: "synthetic teardown failure"}
		return result
	}
	return execution.Result{SchemaVersion: execution.ResultSchemaVersion, JobID: job.Lease.JobId, Status: "passed", Classification: execution.ClassificationPassed, Phase: execution.PhaseCompleted, Cleanup: &execution.CleanupResult{Attempted: true, Succeeded: true}, StartedAt: time.Now(), CompletedAt: time.Now()}
}

func addSecretSelection(t *testing.T, job *runnerv1.JobSpecification) {
	t.Helper()
	var config map[string]json.RawMessage
	if err := json.Unmarshal(job.NormalizedConfigurationJson, &config); err != nil {
		t.Fatal(err)
	}
	tests := make(map[string]json.RawMessage)
	if raw, exists := config["tests"]; exists {
		if err := json.Unmarshal(raw, &tests); err != nil {
			t.Fatal(err)
		}
	}
	tests["secrets"] = json.RawMessage(`{"token":1}`)
	var err error
	config["tests"], err = json.Marshal(tests)
	if err != nil {
		t.Fatal(err)
	}
	job.NormalizedConfigurationJson, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(job.NormalizedConfigurationJson)
	job.Hashes.Configuration.Value = digest[:]
	job.TestSecrets = []*runnerv1.TestSecretReference{{Name: "token", Version: 1, SecretId: "70000000-0000-0000-0000-000000000001"}}
}

func TestSecretStreamAcceptedLeaseDeliveryAndDisconnectCleanup(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		disconnect  bool
		failCleanup bool
	}{
		{name: "completion"},
		{name: "disconnect", disconnect: true},
		{name: "disconnect preserves cleanup failure", disconnect: true, failCleanup: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			disconnect := scenario.disconnect
			now := time.Now().UTC()
			offer := validLeaseOffer(now)
			addSecretSelection(t, offer.Job)
			offer.Job.JobCorrelation = validJobCorrelation(offer)
			worker := &exchangeWorker{wait: disconnect, failCleanup: scenario.failCleanup, started: make(chan struct{}), files: make(chan *testsecrets.Files, 1)}
			serverResult := make(chan error, 1)
			server := &testGateway{connect: func(stream grpc.BidiStreamingServer[runnerv1.RunnerMessage, runnerv1.GatewayMessage]) (err error) {
				defer func() { serverResult <- err }()
				if _, err := stream.Recv(); err != nil {
					return err
				}
				authenticated := authenticatedMessage(now, platformScope())
				authenticated.GetAuthenticated().LeaseDuration = durationpb.New(10 * time.Minute)
				if err := stream.Send(authenticated); err != nil {
					return err
				}
				caps, err := stream.Recv()
				if err != nil || !advertisedFeature(caps.GetCapabilities().GetFeatures(), runnerv1.ProtocolFeature_PROTOCOL_FEATURE_TEST_SECRETS_V1) {
					return errors.New("secret capability missing")
				}
				hb, err := stream.Recv()
				if err != nil || hb.GetHeartbeat() == nil {
					return errors.New("heartbeat missing")
				}
				if err := stream.Send(uniqueGatewayMessage(now, "hb-ack", &runnerv1.GatewayMessage_HeartbeatAcknowledgement{HeartbeatAcknowledgement: &runnerv1.HeartbeatAcknowledgement{RunnerMessageId: hb.MessageId, Sequence: hb.GetHeartbeat().Sequence, CommittedAt: timestamppb.New(now)}})); err != nil {
					return err
				}
				if err := stream.Send(uniqueGatewayMessage(now, "secret-offer", &runnerv1.GatewayMessage_Offer{Offer: offer})); err != nil {
					return err
				}
				accepted, err := stream.Recv()
				if err != nil || accepted.GetLeaseAccepted() == nil {
					return errors.New("secret offer not accepted")
				}
				if err := stream.Send(eventAcknowledgement(now, "secret-accepted", accepted, runnerv1.LeaseStatus_LEASE_STATUS_ACCEPTED, runnerv1.JobPhase_JOB_PHASE_ACCEPTED)); err != nil {
					return err
				}
				preparing, err := stream.Recv()
				if err != nil || preparing.GetJobPreparing() == nil {
					return errors.New("preparation missing")
				}
				if err := stream.Send(eventAcknowledgement(now, "secret-preparing", preparing, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_PREPARING)); err != nil {
					return err
				}
				request, err := stream.Recv()
				if err != nil || request.GetTestSecretsRequest() == nil || !proto.Equal(request.GetTestSecretsRequest().Lease, offer.Job.Lease) {
					return errors.New("secret request missing or wrong lease")
				}
				value := bytes.Repeat([]byte("x"), 65536)
				delivery := &runnerv1.GatewayMessage{MessageId: "delivered", SentAt: timestamppb.New(now), Payload: &runnerv1.GatewayMessage_TestSecretsDelivery{TestSecretsDelivery: &runnerv1.TestSecretsDelivery{RequestMessageId: request.MessageId, Lease: offer.Job.Lease, Attempt: offer.Job.Attempt, ExpiresAt: offer.Job.Lease.ExpiresAt, Secrets: []*runnerv1.TestSecretValue{{Reference: offer.Job.TestSecrets[0], Value: value}}}}}
				if err := stream.Send(delivery); err != nil {
					return err
				}
				clear(value)
				started, err := stream.Recv()
				if err != nil || started.GetJobStarted() == nil {
					return errors.New("start missing")
				}
				select {
				case <-worker.started:
					return errors.New("worker started before committed acknowledgement")
				default:
				}
				if err := stream.Send(eventAcknowledgement(now, "secret-started", started, runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, runnerv1.JobPhase_JOB_PHASE_RUNNING)); err != nil {
					return err
				}
				select {
				case <-worker.started:
				case <-stream.Context().Done():
					return stream.Context().Err()
				}
				if disconnect {
					return status.Error(codes.Unavailable, "synthetic disconnect")
				}
				completed, err := stream.Recv()
				if err != nil || completed.GetCompleted() == nil {
					return errors.New("completion missing")
				}
				if err := stream.Send(eventAcknowledgement(now, "secret-completed", completed, runnerv1.LeaseStatus_LEASE_STATUS_COMPLETED, runnerv1.JobPhase_JOB_PHASE_RUNNING)); err != nil {
					return err
				}
				return stream.Send(uniqueGatewayMessage(now, "secret-shutdown", &runnerv1.GatewayMessage_Shutdown{Shutdown: &runnerv1.ShutdownRunner{ShutdownId: "shutdown", Deadline: timestamppb.New(now.Add(time.Minute))}}))
			}}
			client, closeConnection := bufconnClient(t, server)
			defer closeConnection()
			client.worker = worker
			client.config.EnableTestSecrets = true
			client.config.DisableTerminalEvidence = true
			client.config.Resources.CPUMillis = 2000
			client.connector.(*generatedConnector).allowTestSecrets = true
			client.now = func() time.Time { return now }
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := client.runSession(ctx)
			if err == nil || (!disconnect && !errors.Is(err, ErrServerShutdown)) {
				select {
				case serverErr := <-serverResult:
					t.Fatalf("stream failed: %v; server: %v", err, serverErr)
				default:
					t.Fatalf("stream failed: %v", err)
				}
			}
			joined := make(chan struct{})
			go func() { client.workerWG.Wait(); close(joined) }()
			select {
			case <-joined:
			case <-ctx.Done():
				t.Fatal("secret worker did not stop")
			}
			select {
			case files := <-worker.files:
				if _, err := files.Mounts(); err == nil {
					t.Fatal("worker retained secret files")
				}
			default:
				t.Fatal("worker never acquired files")
			}
			if disconnect {
				select {
				case event := <-client.workerEvents:
					wantCode := "test_secret_connection_lost"
					if scenario.failCleanup {
						wantCode = "synthetic_cleanup_failed"
					}
					if event.result == nil || event.result.Classification != execution.ClassificationInfrastructureFailure || event.result.Failure == nil || event.result.Failure.Code != wantCode {
						t.Fatal("disconnect did not produce retryable infrastructure result")
					}
					if scenario.failCleanup {
						if event.result.Cleanup == nil || event.result.Cleanup.Succeeded || event.result.Cleanup.Error != "synthetic teardown failure" {
							t.Fatal("disconnect concealed cleanup failure")
						}
						// Process the result on a replacement session: disconnected cleanup
						// must quarantine the slot before it can accept another lease.
						replacement := &clientSession{client: client, send: func(*runnerv1.RunnerMessage) error { return nil }}
						if err := replacement.handleWorkerEvent(event); err != nil {
							t.Fatal(err)
						}
						if !client.draining.Load() || client.capacity().AvailableJobs != 0 {
							t.Fatal("disconnect cleanup failure returned capacity")
						}
					}
				default:
					t.Fatal("missing disconnect result")
				}
				client.markWorkerStopped()
			} else if client.journal.snapshot().Active != nil {
				t.Fatal("terminal journal not cleared")
			}
		})
	}
}

func TestSecretCapabilityRequiresExplicitGateAndSupportingWorker(t *testing.T) {
	client := newClient(validConfig(), nil)
	defer client.Close()
	want := runnerv1.ProtocolFeature_PROTOCOL_FEATURE_TEST_SECRETS_V1
	client.worker = &exchangeWorker{}
	if advertisedFeature(client.capabilities().Features, want) {
		t.Fatal("default advertised incomplete rollout")
	}
	client.config.EnableTestSecrets = true
	if !advertisedFeature(client.capabilities().Features, want) || validateAdvertisedFeatures(client.capabilities().Features) != nil {
		t.Fatal("enabled capable worker not negotiated")
	}
	client.worker = nil
	if advertisedFeature(client.capabilities().Features, want) {
		t.Fatal("missing worker advertised secret support")
	}
}

func TestSecretAcceptanceGateCannotRoundTripThroughConfiguration(t *testing.T) {
	config := validConfig()
	config.EnableTestSecrets = true
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.EnableTestSecrets || bytes.Contains(bytes.ToLower(encoded), []byte("testsecrets")) {
		t.Fatal("private acceptance gate escaped into configuration")
	}
	for _, key := range []string{"enableTestSecrets", "EnableTestSecrets", "testSecretsV1"} {
		var injected Config
		if err := json.Unmarshal([]byte(`{"`+key+`":true}`), &injected); err != nil {
			t.Fatal(err)
		}
		if injected.EnableTestSecrets {
			t.Fatal("configuration enabled an unaccepted rollout")
		}
	}
}

func TestEnabledSecretCodecRetainsOtherBoundsAndRejectsOverwrite(t *testing.T) {
	s, request, _ := secretExchangeFixture(t)
	if err := s.beginSecretRequest(request); err != nil {
		t.Fatal(err)
	}
	message, _ := secretExchangeDelivery(s)
	wire, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	codec := strictProtocolCodec{allowTestSecrets: true}
	decoded := new(runnerv1.GatewayMessage)
	if err := codec.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	clearTestSecretDelivery(decoded)
	ordinary := authenticatedMessage(s.client.now(), platformScope())
	ordinary.MessageId = string(bytes.Repeat([]byte("x"), MaximumMessageBytes))
	oversized, err := proto.Marshal(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	if codec.Unmarshal(oversized, new(runnerv1.GatewayMessage)) == nil {
		t.Fatal("ordinary message bound relaxed")
	}
	for _, bad := range [][]byte{
		append(bytes.Clone(wire), wire...),
		protowire.AppendBytes(protowire.AppendTag(bytes.Clone(wire), 10, protowire.BytesType), nil),
	} {
		if codec.Unmarshal(bad, new(runnerv1.GatewayMessage)) == nil {
			t.Fatal("duplicate or overridden delivery accepted")
		}
	}
	value := protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), []byte("first"))
	value = protowire.AppendBytes(protowire.AppendTag(value, 2, protowire.BytesType), []byte("second"))
	delivery := protowire.AppendBytes(protowire.AppendTag(nil, 4, protowire.BytesType), value)
	bad := protowire.AppendBytes(protowire.AppendTag(nil, 32, protowire.BytesType), delivery)
	if codec.Unmarshal(bad, new(runnerv1.GatewayMessage)) == nil {
		t.Fatal("overwritten secret value accepted")
	}
	s.abandonSecretRequest()
}

func TestCleanupFailureQuarantinesSlotAcrossSessionReplacement(t *testing.T) {
	client := newClient(validConfig(), nil)
	defer client.Close()
	first := &clientSession{client: client}
	result := &execution.Result{Cleanup: &execution.CleanupResult{Attempted: true, Succeeded: false, Error: "synthetic teardown failure"}}
	if err := first.handleWorkerEvent(workerEvent{result: result}); err != nil {
		t.Fatal(err)
	}
	if !client.draining.Load() || client.capacity().AvailableJobs != 0 {
		t.Fatal("failed cleanup returned capacity")
	}
	var sent []*runnerv1.RunnerMessage
	now := time.Now().UTC()
	next := &clientSession{client: client, send: func(m *runnerv1.RunnerMessage) error { sent = append(sent, m); return nil }, reconciled: true}
	if err := next.handleOffer(uniqueGatewayMessage(now, "after-cleanup-failure", &runnerv1.GatewayMessage_Offer{Offer: validLeaseOffer(now)}), now); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0].GetLeaseRejected().GetReason() != runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_DRAINING {
		t.Fatal("replacement session reused quarantined slot")
	}
}
