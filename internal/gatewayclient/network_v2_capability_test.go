package gatewayclient

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type networkCapableWorker struct{ maximum *p.EffectivePolicy }

func (*networkCapableWorker) Execute(context.Context, *p.JobSpecification, func(context.Context, execution.ExecutionStart) error) execution.Result {
	panic("offer must not start execution")
}
func (*networkCapableWorker) ExecuteV2(context.Context, *p.JobSpecification, func(context.Context, execution.ExecutionStart) error) execution.Result {
	panic("offer must not start execution")
}
func (w *networkCapableWorker) MeasuredNetworkMaximum() *p.EffectivePolicy { return w.maximum }

func TestNetworkAdvertisementUsesCopiedRootMaximumAndOptIn(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	offer, _, _ := networkV2OfferFixture(t, now, p.NetworkMode_NETWORK_MODE_ALLOWLIST)
	maximum := proto.Clone(offer.Job.EffectivePolicy).(*p.EffectivePolicy)
	worker := &networkCapableWorker{maximum: maximum}
	config := validConfig()
	config.Resources = validOfferConfig().Resources
	config.EnableTerminalEvidenceV2 = true
	client, err := newClientWithWorker(config, nil, worker)
	if err != nil {
		t.Fatal(err)
	}
	firstClient := client
	t.Cleanup(func() { firstClient.Close() })
	if advertisedFeature(client.capabilities().Features, p.ProtocolFeature_PROTOCOL_FEATURE_NETWORK_POLICY_V2) {
		t.Fatal("implicit network advertisement")
	}
	config.EnableNetworkPolicyV2 = true
	client, err = newClientWithWorker(config, nil, worker)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	capabilities := client.capabilities()
	if validateAdvertisedFeatures(capabilities.Features) != nil || !advertisedFeature(capabilities.Features, p.ProtocolFeature_PROTOCOL_FEATURE_NETWORK_AUTHORITY_V2) || capabilities.Policy.MaximumNetwork != nil || !proto.Equal(capabilities.Policy.MaximumNetworkV2, maximum.NetworkV2) || capabilities.Policy.MaximumResourcesPerJob.MemoryBytes != maximum.Resources.MemoryBytes || capabilities.Capacity.MemoryBytes != maximum.Resources.MemoryBytes {
		t.Fatal("advertisement did not use root bounds")
	}
	maximum.NetworkV2.Permissions[0].Hostname = "changed.example.com"
	capabilities.Policy.MaximumNetworkV2.Permissions[0].Hostname = "also-changed.example.com"
	if client.capabilities().Policy.MaximumNetworkV2.Permissions[0].Hostname != "fixture.example.com" {
		t.Fatal("mutable maximum escaped")
	}
	client.config.EnableNetworkPolicyV2 = false
	if advertisedFeature(client.capabilities().Features, p.ProtocolFeature_PROTOCOL_FEATURE_NETWORK_POLICY_V2) {
		t.Fatal("operator rollback ignored")
	}
	client.config.EnableNetworkPolicyV2 = true
	client.config.DisableTerminalEvidence = true
	if advertisedFeature(client.capabilities().Features, p.ProtocolFeature_PROTOCOL_FEATURE_NETWORK_POLICY_V2) {
		t.Fatal("evidence rollback left networking enabled")
	}
	raw, err := json.Marshal(config)
	if err != nil || bytes.Contains(raw, []byte("EnableNetwork")) || bytes.Contains(raw, []byte("enableNetwork")) {
		t.Fatal("operator gate serialized")
	}
}

func TestNetworkAdvertisementRefusesIncompleteProvisioning(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	for _, mode := range []string{"worker", "maximum", "evidence", "rollback", "malformed", "mixed"} {
		offer, _, _ := networkV2OfferFixture(t, now, p.NetworkMode_NETWORK_MODE_ALLOWLIST)
		config := validConfig()
		config.EnableNetworkPolicyV2, config.EnableTerminalEvidenceV2 = true, true
		worker := &networkCapableWorker{maximum: offer.Job.EffectivePolicy}
		var remote RemoteWorker = worker
		switch mode {
		case "worker":
			remote = &versionRecordingWorker{}
		case "maximum":
			worker.maximum = nil
		case "evidence":
			config.EnableTerminalEvidenceV2 = false
		case "rollback":
			config.DisableTerminalEvidence = true
		case "malformed":
			worker.maximum.NetworkV2.MaximumConnections = 0
		case "mixed":
			worker.maximum.Network = &p.NetworkPolicy{Mode: p.NetworkMode_NETWORK_MODE_NONE}
		}
		if client, err := newClientWithWorker(config, nil, remote); err == nil || client != nil {
			t.Fatal("incomplete network provisioning accepted", mode)
		}
	}
}

func TestNetworkOfferSessionPersistsOriginalOnlyAfterAllChecks(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	for _, mode := range []string{"accepted", "none", "missing-feature", "missing-root", "timeout", "configuration", "scope"} {
		t.Run(mode, func(t *testing.T) {
			networkMode := p.NetworkMode_NETWORK_MODE_ALLOWLIST
			if mode == "none" {
				networkMode = p.NetworkMode_NETWORK_MODE_NONE
			}
			offer, _, _ := networkV2OfferFixture(t, now, networkMode)
			maximum := proto.Clone(offer.Job.EffectivePolicy).(*p.EffectivePolicy)
			config := validConfig()
			config.journalFile = filepath.Join(t.TempDir(), "runner-journal.json")
			config.EnableNetworkPolicyV2, config.EnableTerminalEvidenceV2 = true, true
			config.Resources = validOfferConfig().Resources
			client, err := newClientWithWorker(config, nil, &networkCapableWorker{maximum: maximum})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Close() })
			authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
			authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
			var sent []*p.RunnerMessage
			session := &clientSession{client: client, authenticated: authenticated, terminalEvidenceV1: true, terminalEvidenceV2: true, jobCorrelationV1: true, networkFeatures: client.capabilities().Features, networkMaximum: cloneNetworkMaximum(client.networkMaximum), rootContext: context.Background(), send: func(message *p.RunnerMessage) error {
				sent = append(sent, proto.Clone(message).(*p.RunnerMessage))
				return nil
			}}
			switch mode {
			case "missing-feature":
				session.networkFeatures = []p.ProtocolFeature{1, 3, 7, 9}
			case "missing-root":
				session.networkMaximum = nil
			case "timeout":
				session.networkMaximum.ExecutionTimeout = durationpb.New(time.Second)
			case "configuration":
				offer.Job.Hashes.Configuration.Value[0] ^= 1
			case "scope":
				client.config.ExpectedScope = ExpectedScope{Kind: ScopeOrganization, OrganizationID: "b1111111-1111-4111-8111-111111111111"}
			}
			before := proto.Clone(offer)
			message := uniqueGatewayMessage(now, "network-offer", &p.GatewayMessage_Offer{Offer: offer})
			if err := session.handleOffer(message, now); err != nil {
				t.Fatal(err)
			}
			accepted := mode == "accepted" || mode == "none"
			state := client.journal.snapshot()
			if len(sent) != 1 || (state.Active != nil) != accepted || (sent[0].GetLeaseAccepted() != nil) != accepted || !proto.Equal(before, offer) {
				t.Fatal("incorrect durable admission", mode)
			}
			if accepted {
				var stored p.JobSpecification
				if proto.Unmarshal(state.Active.Specification, &stored) != nil || !state.Active.TerminalEvidenceV2 || stored.CompleteLogUpload != nil || !proto.Equal(stored.EffectivePolicy, offer.Job.EffectivePolicy) || !proto.Equal(stored.Hashes, offer.Job.Hashes) || client.workerNetworkAuthority != nil {
					t.Fatal("offer changed identity or manufactured authority")
				}
				reopened, err := newClientWithWorker(config, nil, &networkCapableWorker{maximum: maximum})
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				recovered := reopened.journal.snapshot()
				if !reopened.recovering || reopened.workerNetworkAuthority != nil || recovered.Active == nil || !recovered.Active.TerminalEvidenceV2 || !bytes.Equal(recovered.Active.Specification, state.Active.Specification) || !bytes.Equal(recovered.PendingMessage, state.PendingMessage) {
					t.Fatal("restart changed accepted bytes or reconstructed authority")
				}
			}
		})
	}
}
