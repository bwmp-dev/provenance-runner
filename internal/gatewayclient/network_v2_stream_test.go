package gatewayclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type networkStreamWorker struct{ entered chan *np.AuthorityRoute }

func (*networkStreamWorker) Execute(context.Context, *p.JobSpecification, func(context.Context, execution.ExecutionStart) error) execution.Result {
	panic("legacy worker selected")
}
func (w *networkStreamWorker) ExecuteV2(ctx context.Context, job *p.JobSpecification, _ func(context.Context, execution.ExecutionStart) error) execution.Result {
	guard := execution.NetworkAuthorityRoute(ctx)
	if guard == nil || guard.CheckJob(job) != nil {
		panic("worker entered without current authority")
	}
	w.entered <- guard
	<-ctx.Done()
	result := execution.FailedResult(job.Lease.JobId, execution.PhasePreparation, execution.ClassificationCancelled, "synthetic_stream_stopped", context.Canceled)
	result.Cleanup = &execution.CleanupResult{Attempted: true, Succeeded: true}
	return result
}

// Real generated gRPC transport and supervisor; the worker deliberately never
// launches a guest. Root execution is covered by the separate disposable suite.
func TestNetworkV2StreamRequiresFreshReceiptAndDisconnectWithdraws(t *testing.T) {
	for _, mode := range []string{"current", "missing", "expired"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			offer, _, _ := networkV2OfferFixture(t, now, p.NetworkMode_NETWORK_MODE_ALLOWLIST)
			worker := &networkStreamWorker{entered: make(chan *np.AuthorityRoute, 1)}
			serverResult := make(chan error, 1)
			var received *np.AuthorityRoute
			gateway := &testGateway{connect: func(stream grpc.BidiStreamingServer[p.RunnerMessage, p.GatewayMessage]) (err error) {
				defer func() { serverResult <- err }()
				if _, err := stream.Recv(); err != nil {
					return err
				}
				auth := authenticatedMessage(now, platformScope())
				auth.GetAuthenticated().LeaseDuration = durationpb.New(10 * time.Minute)
				if err := stream.Send(auth); err != nil {
					return err
				}
				caps, err := stream.Recv()
				if err != nil || validateAdvertisedFeatures(caps.GetCapabilities().GetFeatures()) != nil || !advertisedFeature(caps.GetCapabilities().GetFeatures(), p.ProtocolFeature_PROTOCOL_FEATURE_NETWORK_AUTHORITY_V2) || !proto.Equal(caps.GetCapabilities().GetPolicy().GetMaximumNetworkV2(), offer.Job.EffectivePolicy.NetworkV2) {
					return errors.New("network capabilities missing")
				}
				hb, err := stream.Recv()
				if err != nil || hb.GetHeartbeat() == nil {
					return errors.New("heartbeat missing")
				}
				if err := stream.Send(uniqueGatewayMessage(now, "network-hb", &p.GatewayMessage_HeartbeatAcknowledgement{HeartbeatAcknowledgement: &p.HeartbeatAcknowledgement{RunnerMessageId: hb.MessageId, Sequence: hb.GetHeartbeat().Sequence, CommittedAt: timestamppb.New(now)}})); err != nil {
					return err
				}
				if err := stream.Send(uniqueGatewayMessage(now, "network-offer", &p.GatewayMessage_Offer{Offer: offer})); err != nil {
					return err
				}
				accepted, err := stream.Recv()
				if err != nil || accepted.GetLeaseAccepted() == nil {
					return errors.New("network offer not accepted")
				}
				select {
				case <-worker.entered:
					return errors.New("offer alone started worker")
				default:
				}
				acknowledge := func(message *p.RunnerMessage, name string, status p.LeaseStatus, phase p.JobPhase) error {
					ack := eventAcknowledgement(now, name, message, status, phase)
					if mode != "missing" {
						grant := &p.NetworkAuthorityV2{Policy: proto.Clone(offer.Job.Hashes.Policy).(*p.Digest), State: p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT, CheckedAt: timestamppb.New(time.Now()), ExpiresAt: timestamppb.New(time.Now().Add(30 * time.Second))}
						if mode == "expired" {
							grant.ExpiresAt = timestamppb.New(time.Now().Add(-time.Second))
						}
						ack.GetEventAcknowledgement().Reconciliation.NetworkAuthorityV2 = grant
					}
					return stream.Send(ack)
				}
				if err := acknowledge(accepted, "network-accepted", p.LeaseStatus_LEASE_STATUS_ACCEPTED, p.JobPhase_JOB_PHASE_ACCEPTED); err != nil {
					return err
				}
				if mode != "current" {
					_, err := stream.Recv()
					return err
				}
				preparing, err := stream.Recv()
				if err != nil || preparing.GetJobPreparing() == nil {
					return errors.New("network preparation missing")
				}
				if err := acknowledge(preparing, "network-preparing", p.LeaseStatus_LEASE_STATUS_ACTIVE, p.JobPhase_JOB_PHASE_PREPARING); err != nil {
					return err
				}
				select {
				case received = <-worker.entered:
				case <-stream.Context().Done():
					return stream.Context().Err()
				}
				return status.Error(codes.Unavailable, "synthetic network disconnect")
			}}
			client, closeConnection := bufconnClient(t, gateway)
			defer closeConnection()
			defer client.Close()
			client.worker = worker
			client.config.EnableNetworkPolicyV2, client.config.EnableTerminalEvidenceV2 = true, true
			client.config.Resources = validOfferConfig().Resources
			client.networkMaximum = proto.Clone(offer.Job.EffectivePolicy).(*p.EffectivePolicy)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := client.runSession(ctx); err == nil {
				t.Fatal("invalid authority or disconnect ignored")
			}
			select {
			case <-serverResult:
			case <-ctx.Done():
				t.Fatal("gateway did not finish")
			}
			client.workerWG.Wait()
			if mode != "current" {
				select {
				case <-worker.entered:
					t.Fatal("missing/expired grant started worker")
				default:
				}
				return
			}
			if received == nil || received.CheckJob(offer.Job) == nil {
				t.Fatal("disconnect retained current grant")
			}
			select {
			case event := <-client.workerEvents:
				if event.result == nil || event.result.Failure == nil || event.result.Failure.Code != "network_authority_lost" || event.result.Cleanup == nil || !event.result.Cleanup.Succeeded {
					t.Fatal("disconnect lost infrastructure failure/cleanup")
				}
			default:
				t.Fatal("missing disconnected worker result")
			}
			if client.journal.snapshot().Active == nil {
				t.Fatal("disconnect invented terminal acknowledgement")
			}
			client.markWorkerStopped()
		})
	}
}
