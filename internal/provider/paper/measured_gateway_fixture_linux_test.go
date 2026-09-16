//go:build linux

package paper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/gatewayclient"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type measuredGatewayFixtureWorker struct {
	provider *Provider
	endpoint string
	maximum  *p.EffectivePolicy
	starts   atomic.Uint32
	result   chan execution.Result
}

func (*measuredGatewayFixtureWorker) Execute(context.Context, *p.JobSpecification, func(context.Context, execution.ExecutionStart) error) execution.Result {
	panic("fixture selected legacy execution")
}
func (w *measuredGatewayFixtureWorker) MeasuredNetworkMaximum() *p.EffectivePolicy {
	return proto.Clone(w.maximum).(*p.EffectivePolicy)
}
func (w *measuredGatewayFixtureWorker) ExecuteV2(ctx context.Context, job *p.JobSpecification, before func(context.Context, execution.ExecutionStart) error) execution.Result {
	result := w.provider.ExecuteMeasured(ctx, job, w.endpoint, func(ctx context.Context, start execution.ExecutionStart) error {
		w.starts.Add(1)
		return before(ctx, start)
	})
	w.result <- result
	return result
}

type measuredGatewayFixtureServer struct {
	p.UnimplementedRunnerGatewayServer
	connect func(grpc.BidiStreamingServer[p.RunnerMessage, p.GatewayMessage]) error
}

func (s *measuredGatewayFixtureServer) Connect(stream grpc.BidiStreamingServer[p.RunnerMessage, p.GatewayMessage]) error {
	return s.connect(stream)
}

// Uses the production gateway client and Paper provider with an in-memory
// generated gRPC server. Root execution is real; this is not platform/database
// acceptance and intentionally does not claim object-storage upload acceptance.
func runMeasuredGatewayFixture(t *testing.T, ctx context.Context, provider *Provider, endpoint string, job *p.JobSpecification) {
	t.Helper()
	if os.Getenv("PROVENANCE_DISPOSABLE_REAL_PAPER_FIXTURE") != "1" || len(job.TestSecrets) != 0 {
		t.Fatal("plain real Paper gateway fixture required")
	}
	const runnerID = "50000000-0000-4000-8000-000000000001"
	// The direct-root fixture uses distinct identifiers; gateway offers use the
	// platform invariant that a job is its execution, with a separate lease.
	job.Lease.ExecutionId = job.Lease.JobId
	rootDigest, err := hex.DecodeString(os.Getenv("PROVENANCE_DISPOSABLE_GATEWAY_ROOTFS"))
	if err != nil || len(rootDigest) != sha256.Size {
		t.Fatal("missing pinned fixture image")
	}
	job.Environment.RunnerImage = &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: rootDigest}
	job.Environment.CatalogSnapshotId = "60000000-0000-4000-8000-000000000001"
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(job.Environment)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	job.Hashes.Environment = &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}
	scope := &p.OrganizationScope{Scope: &p.OrganizationScope_Platform{Platform: &emptypb.Empty{}}}
	job.OrganizationScope = scope
	job.JobCorrelation = &p.JobCorrelation{Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", OrganizationId: "60000000-0000-4000-8000-000000000002", ProjectId: "70000000-0000-4000-8000-000000000001", WorkflowId: "release/" + job.Attempt.ReleaseCandidateId}
	job.Artifact.ExpiresAt = timestamppb.New(job.Lease.ExpiresAt.AsTime().Add(time.Minute))
	maximum, err := provider.ReadMeasuredMaximum(ctx, endpoint)
	if err != nil {
		t.Fatal("root-confirmed gateway maximum", err)
	}
	worker := &measuredGatewayFixtureWorker{provider: provider, endpoint: endpoint, maximum: maximum, result: make(chan execution.Result, 1)}
	serverResult := make(chan error, 1)
	terminalSeen := false
	server := &measuredGatewayFixtureServer{connect: func(stream grpc.BidiStreamingServer[p.RunnerMessage, p.GatewayMessage]) (result error) {
		defer func() { serverResult <- result }()
		sequence := 0
		message := func() *p.GatewayMessage {
			sequence++
			return &p.GatewayMessage{MessageId: fmt.Sprintf("fixture-%d", sequence), SentAt: timestamppb.Now()}
		}
		first, err := stream.Recv()
		if err != nil || first.GetAuthenticate().GetRunnerId() != runnerID {
			return errors.New("fixture authentication missing")
		}
		auth := message()
		auth.Payload = &p.GatewayMessage_Authenticated{Authenticated: &p.Authenticated{RunnerId: runnerID, ConnectionId: "60000000-0000-4000-8000-000000000003", OrganizationScope: scope, CredentialExpiresAt: timestamppb.New(time.Now().Add(time.Hour)), HeartbeatInterval: durationpb.New(5 * time.Second), LeaseDuration: durationpb.New(10 * time.Minute), ServerTime: timestamppb.Now(), ProtocolVersion: "1"}}
		if err := stream.Send(auth); err != nil {
			return err
		}
		caps, err := stream.Recv()
		if err != nil || !proto.Equal(caps.GetCapabilities().GetPolicy().GetMaximumNetworkV2(), maximum.NetworkV2) {
			return errors.New("fixture network capabilities missing")
		}
		offered, accepted := false, false
		phase, state := p.JobPhase_JOB_PHASE_ACCEPTED, p.LeaseStatus_LEASE_STATUS_ACCEPTED
		reconcile := func() *p.LeaseReconciliation {
			now := time.Now()
			r := &p.LeaseReconciliation{Lease: proto.Clone(job.Lease).(*p.LeaseIdentity), Attempt: proto.Clone(job.Attempt).(*p.AttemptIdentity), Status: state, Phase: phase, Disposition: p.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED}
			if state == p.LeaseStatus_LEASE_STATUS_ACCEPTED || state == p.LeaseStatus_LEASE_STATUS_ACTIVE {
				expiry := now.Add(40 * time.Second)
				if job.Lease.ExpiresAt.AsTime().Before(expiry) {
					expiry = job.Lease.ExpiresAt.AsTime()
				}
				r.NetworkAuthorityV2 = &p.NetworkAuthorityV2{Policy: proto.Clone(job.Hashes.Policy).(*p.Digest), State: p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT, CheckedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(expiry)}
			}
			return r
		}
		for {
			incoming, err := stream.Recv()
			if err != nil {
				return err
			}
			if hb := incoming.GetHeartbeat(); hb != nil {
				ack := &p.HeartbeatAcknowledgement{RunnerMessageId: incoming.MessageId, Sequence: hb.Sequence, CommittedAt: timestamppb.Now()}
				if len(hb.ActiveLeases) != 0 {
					ack.Reconciliations = []*p.LeaseReconciliation{reconcile()}
				}
				out := message()
				out.Payload = &p.GatewayMessage_HeartbeatAcknowledgement{HeartbeatAcknowledgement: ack}
				if err := stream.Send(out); err != nil {
					return err
				}
				if !offered {
					out := message()
					out.Payload = &p.GatewayMessage_Offer{Offer: &p.LeaseOffer{OfferExpiresAt: timestamppb.New(time.Now().Add(15 * time.Second)), Job: job}}
					if err := stream.Send(out); err != nil {
						return err
					}
					offered = true
				}
				continue
			}
			switch {
			case incoming.GetLeaseAccepted() != nil:
				if accepted || worker.starts.Load() != 0 {
					return errors.New("fixture execution preceded acceptance acknowledgement")
				}
				accepted = true
			case incoming.GetJobPreparing() != nil:
				phase, state = p.JobPhase_JOB_PHASE_PREPARING, p.LeaseStatus_LEASE_STATUS_ACTIVE
			case incoming.GetJobStarted() != nil:
				phase = p.JobPhase_JOB_PHASE_RUNNING
			case incoming.GetLogBatch() != nil, incoming.GetUsage() != nil:
				// Live observations are not durable events and receive no event ACK.
				continue
			case incoming.GetLeaseRenewal() != nil:
			case incoming.GetCompleted() != nil:
				completed := incoming.GetCompleted()
				if completed.Result.GetOutcome() != p.ResultOutcome_RESULT_OUTCOME_PASSED || terminalevidence.ValidateFrozenV2(completed.ExecutionEvidence, job, runnerID) != nil {
					return errors.New("fixture terminal result or measured v2 evidence invalid")
				}
				state, terminalSeen = p.LeaseStatus_LEASE_STATUS_COMPLETED, true
			case incoming.GetFailed() != nil:
				return fmt.Errorf("fixture execution failed: %s", incoming.GetFailed().GetFailure().GetCode())
			case incoming.GetLeaseRejected() != nil:
				return fmt.Errorf("fixture gateway offer rejected: %s", incoming.GetLeaseRejected().GetSummary())
			default:
				return errors.New("unexpected fixture runner message")
			}
			r := reconcile()
			if terminalSeen {
				r.TerminalMessageId = incoming.MessageId
			}
			out := message()
			out.Payload = &p.GatewayMessage_EventAcknowledgement{EventAcknowledgement: &p.RunnerEventAcknowledgement{RunnerMessageId: incoming.MessageId, Reconciliation: r, CommittedAt: timestamppb.Now()}}
			if err := stream.Send(out); err != nil {
				return err
			}
			if terminalSeen {
				out := message()
				out.Payload = &p.GatewayMessage_Shutdown{Shutdown: &p.ShutdownRunner{ShutdownId: "fixture-complete", Deadline: timestamppb.New(time.Now().Add(time.Minute))}}
				return stream.Send(out)
			}
		}
	}}
	listener := bufconn.Listen(1 << 20)
	rpcServer := grpc.NewServer()
	p.RegisterRunnerGatewayServer(rpcServer, server)
	go func() { _ = rpcServer.Serve(listener) }()
	defer rpcServer.Stop()
	defer listener.Close()
	connection, err := grpc.NewClient("passthrough:///measured-fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	directory := t.TempDir()
	credential := filepath.Join(directory, "credential")
	if os.WriteFile(credential, []byte("synthetic-gateway-fixture-only"), 0600) != nil {
		t.Fatal("fixture credential")
	}
	config := gatewayclient.Config{SchemaVersion: gatewayclient.ConfigSchemaVersion, GatewayAddress: "gateway.fixture:443", RunnerID: runnerID, InstanceID: "measured-fixture", CredentialFile: credential, ExpectedScope: gatewayclient.ExpectedScope{Kind: gatewayclient.ScopePlatform}, Resources: gatewayclient.Resources{CPUMillis: maximum.Resources.CpuMillis, MemoryBytes: maximum.Resources.MemoryBytes, DiskBytes: maximum.Resources.DiskBytes, ProcessCount: maximum.Resources.ProcessCount}}
	raw, err = json.Marshal(config)
	configPath := filepath.Join(directory, "connect.json")
	if err != nil || os.WriteFile(configPath, raw, 0600) != nil {
		t.Fatal("fixture connection configuration")
	}
	config, err = gatewayclient.LoadConfig(configPath, "0.1.0-alpha")
	if err != nil {
		t.Fatal(err)
	}
	config.EnableNetworkPolicyV2, config.EnableTerminalEvidenceV2 = true, true
	client, err := gatewayclient.NewWithWorker(config, p.NewRunnerGatewayClient(connection), worker)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	runErr := client.Run(ctx)
	var serverErr error
	select {
	case serverErr = <-serverResult:
	case <-ctx.Done():
		t.Fatal("fixture gateway did not terminate")
	}
	if !errors.Is(runErr, gatewayclient.ErrServerShutdown) || serverErr != nil || !terminalSeen || worker.starts.Load() != 1 {
		t.Fatalf("measured gateway composition: client=%v server=%v terminal=%t starts=%d", runErr, serverErr, terminalSeen, worker.starts.Load())
	}
	result := <-worker.result
	if !result.Passed() || result.Cleanup == nil || !result.Cleanup.Succeeded || result.MeasuredNetwork == nil {
		t.Fatal("gateway worker lost measured success or cleanup")
	}
	raw, err = os.ReadFile(filepath.Join(directory, ".provenance-runner-journal.json"))
	var journal map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &journal) != nil || len(journal["active"]) != 0 || len(journal["pendingMessage"]) != 0 {
		t.Fatal("terminal acknowledgement did not retire durable gateway state")
	}
	fmt.Println("MEASURED_GATEWAY_PAPER_TERMINAL_OK")
}
