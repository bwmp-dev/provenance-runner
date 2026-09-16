package gatewayclient

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func networkV2OfferFixture(t *testing.T, now time.Time, mode p.NetworkMode) (*p.LeaseOffer, Config, *p.NetworkPolicyV2) {
	t.Helper()
	offer := validLeaseOffer(now)
	job := offer.Job
	job.Dependencies, job.Hashes.Dependencies = nil, nil
	job.JobCorrelation = validJobCorrelation(offer)
	job.EffectivePolicy.Network = nil
	network := &p.NetworkPolicyV2{Mode: mode}
	configurationNetwork := map[string]any{"mode": "none", "permissions": []any{}, "maximumConnections": 0, "maximumBytesPerSecond": 0}
	if mode != p.NetworkMode_NETWORK_MODE_NONE {
		network.MaximumConnections, network.MaximumBytesPerSecond = 8, 65536
		network.Permissions = []*p.NetworkPermissionV2{{Hostname: "fixture.example.com", Port: 443, Transport: p.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP}}
		name := "allowlist"
		if mode == p.NetworkMode_NETWORK_MODE_RESTRICTED {
			name = "restricted"
		}
		configurationNetwork = map[string]any{"mode": name, "permissions": []any{map[string]any{"hostname": "fixture.example.com", "port": 443, "transport": "tcp"}}, "maximumConnections": 8, "maximumBytesPerSecond": 65536}
	}
	job.EffectivePolicy.NetworkV2 = network
	config := map[string]any{
		"apiVersion": "provenance.dev/v2", "project": map[string]any{"id": "fixture", "name": "Fixture"},
		"artifact": map[string]any{"id": "fixture", "path": "build/target.jar", "version": "1.0.0"}, "dependencies": []any{},
		"network": configurationNetwork, "release": map[string]any{"mode": "test-only", "targets": []any{}},
		"paper": map[string]any{
			"matrix":          []any{map[string]any{"id": "paper", "minecraftVersion": "1.21.8", "paperBuild": 60, "javaVersion": 21, "policy": "required"}},
			"recommendations": map[string]any{"apiFloor": "1.21.8", "enabled": false, "newVersions": "informational"},
			"gatePolicy":      map[string]any{"informationalFailure": "report", "infrastructureFailure": "retry", "maxInfrastructureRetries": 2, "requiredFailure": "block"}},
		"tests":     map[string]any{"startup": map[string]any{"timeoutSeconds": 20, "stabilizationSeconds": 1, "requirePluginEnabled": true, "shutdownTimeoutSeconds": 10, "requireCleanShutdown": true}, "console": []any{}},
		"resources": map[string]any{"cpuCores": 1.5, "memoryMiB": 1024, "diskMiB": 2048, "processes": 64, "wallTimeoutSeconds": 60, "logBytes": 1 << 20},
	}
	var err error
	job.NormalizedConfigurationJson, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Configuration = offerDigest(job.NormalizedConfigurationJson)
	networkV2OfferRehash(t, job)
	environment, err := proto.MarshalOptions{Deterministic: true}.Marshal(job.Environment)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Environment = offerDigest(environment)
	settings := validOfferConfig()
	settings.EnableTerminalEvidenceV2 = true
	return offer, settings, proto.Clone(network).(*p.NetworkPolicyV2)
}

func networkV2OfferRehash(t *testing.T, job *p.JobSpecification) {
	t.Helper()
	digest, err := networkpolicy.EffectivePolicyV2SHA256(job.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Policy = &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}
}

func TestNetworkV2OfferExplicitAdmissionPreservesWireIdentity(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	for _, mode := range []p.NetworkMode{p.NetworkMode_NETWORK_MODE_NONE, p.NetworkMode_NETWORK_MODE_RESTRICTED, p.NetworkMode_NETWORK_MODE_ALLOWLIST} {
		offer, config, maximum := networkV2OfferFixture(t, now, mode)
		before, maxBefore := proto.Clone(offer), proto.Clone(maximum)
		if rejection := validateNetworkV2Offer(offer, config, now, 10*time.Minute, []p.ProtocolFeature{1, 3, 7, 9, 10}, maximum); rejection != nil {
			t.Fatal(mode, rejection)
		}
		if !proto.Equal(before, offer) || !proto.Equal(maxBefore, maximum) {
			t.Fatal("admission mutated frozen offer or maximum")
		}
		if rejection := validateOffer(offer, config, now, 10*time.Minute, true, false); rejection == nil || rejection.Code != "unsupported_network" {
			t.Fatal("legacy path widened", rejection)
		}
	}
}

func TestNetworkV2OfferEveryPrerequisiteAndMaximumIsMandatory(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	for _, missing := range []p.ProtocolFeature{1, 3, 7, 9, 10} {
		offer, config, maximum := networkV2OfferFixture(t, now, p.NetworkMode_NETWORK_MODE_ALLOWLIST)
		var features []p.ProtocolFeature
		for _, feature := range []p.ProtocolFeature{1, 3, 7, 9, 10} {
			if feature != missing {
				features = append(features, feature)
			}
		}
		if validateNetworkV2Offer(offer, config, now, 10*time.Minute, features, maximum) == nil {
			t.Fatal("missing feature accepted", missing)
		}
	}
	for _, mode := range []string{"nil", "mixed", "unrestricted", "nil-maximum", "malformed-maximum-none", "wider-host", "wider-port", "wider-transport", "wider-connections", "wider-rate", "policy-hash", "environment-hash", "config-hash", "unknown-config", "configuration-denies-network", "missing-correlation", "disabled-proof", "rollback-proof", "unknown-feature", "duplicate-feature", "secret-reference", "legacy-policy", "expired", "oversize", "resource-cap", "scope", "unknown-policy-field"} {
		t.Run(mode, func(t *testing.T) {
			offer, config, maximum := networkV2OfferFixture(t, now, p.NetworkMode_NETWORK_MODE_ALLOWLIST)
			features := []p.ProtocolFeature{1, 3, 7, 9, 10}
			switch mode {
			case "nil":
				offer = nil
			case "mixed":
				offer.Job.EffectivePolicy.Network = &p.NetworkPolicy{Mode: p.NetworkMode_NETWORK_MODE_NONE}
			case "unrestricted":
				offer.Job.EffectivePolicy.NetworkV2.Mode = p.NetworkMode_NETWORK_MODE_UNRESTRICTED
			case "nil-maximum":
				maximum = nil
			case "malformed-maximum-none":
				offer, config, maximum = networkV2OfferFixture(t, now, p.NetworkMode_NETWORK_MODE_NONE)
				maximum.MaximumConnections = 1
			case "wider-host":
				maximum.Permissions[0].Hostname = "other.example.com"
			case "wider-port":
				maximum.Permissions[0].Port = 8443
			case "wider-transport":
				maximum.Permissions[0].Transport = p.NetworkTransportV2_NETWORK_TRANSPORT_V2_UDP
			case "wider-connections":
				maximum.MaximumConnections = 4
			case "wider-rate":
				maximum.MaximumBytesPerSecond = 32768
			case "policy-hash":
				offer.Job.Hashes.Policy.Value[0] ^= 1
			case "environment-hash":
				offer.Job.Hashes.Environment.Value[0] ^= 1
			case "config-hash":
				offer.Job.Hashes.Configuration.Value[0] ^= 1
			case "unknown-config":
				var document map[string]any
				json.Unmarshal(offer.Job.NormalizedConfigurationJson, &document)
				document["unknown"] = true
				offer.Job.NormalizedConfigurationJson, _ = json.Marshal(document)
				offer.Job.Hashes.Configuration = offerDigest(offer.Job.NormalizedConfigurationJson)
			case "configuration-denies-network":
				var document map[string]any
				json.Unmarshal(offer.Job.NormalizedConfigurationJson, &document)
				document["network"] = map[string]any{"mode": "none", "permissions": []any{}, "maximumConnections": 0, "maximumBytesPerSecond": 0}
				offer.Job.NormalizedConfigurationJson, _ = json.Marshal(document)
				offer.Job.Hashes.Configuration = offerDigest(offer.Job.NormalizedConfigurationJson)
			case "missing-correlation":
				offer.Job.JobCorrelation = nil
			case "disabled-proof":
				config.EnableTerminalEvidenceV2 = false
			case "rollback-proof":
				config.DisableTerminalEvidence = true
			case "unknown-feature":
				features = append(features, 127)
			case "duplicate-feature":
				features = append(features, 10)
			case "secret-reference":
				config.EnableTestSecrets = true
				features = append(features, p.ProtocolFeature_PROTOCOL_FEATURE_TEST_SECRETS_V1)
				offer.Job.TestSecrets = []*p.TestSecretReference{{Name: "license", SecretId: "b1111111-1111-4111-8111-111111111111", Version: 1}}
			case "legacy-policy":
				offer.Job.EffectivePolicy.NetworkV2 = nil
				offer.Job.EffectivePolicy.Network = &p.NetworkPolicy{Mode: p.NetworkMode_NETWORK_MODE_NONE}
			case "expired":
				offer.OfferExpiresAt.Seconds = now.Unix() - 1
			case "oversize":
				offer.Job.NormalizedConfigurationJson = make([]byte, MaximumMessageBytes+1)
			case "resource-cap":
				config.Resources.MemoryBytes = 16 << 20
			case "scope":
				config.ExpectedScope = ExpectedScope{Kind: ScopeOrganization, OrganizationID: "b1111111-1111-4111-8111-111111111111"}
			case "unknown-policy-field":
				offer.Job.EffectivePolicy.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
			}
			var before proto.Message
			if offer != nil {
				before = proto.Clone(offer)
			}
			if rejection := validateNetworkV2Offer(offer, config, now, 10*time.Minute, features, maximum); rejection == nil {
				t.Fatal("invalid offer accepted")
			}
			if offer != nil && !proto.Equal(before, offer) {
				t.Fatal("refusal mutated offer")
			}
		})
	}
}

func TestNetworkV2OfferSecretNegotiationAndSelectionRemainIndependent(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	offer, config, maximum := networkV2OfferFixture(t, now, p.NetworkMode_NETWORK_MODE_ALLOWLIST)
	var document map[string]any
	if json.Unmarshal(offer.Job.NormalizedConfigurationJson, &document) != nil {
		t.Fatal("fixture")
	}
	document["tests"].(map[string]any)["secrets"] = map[string]uint64{"license": 1}
	offer.Job.NormalizedConfigurationJson, _ = json.Marshal(document)
	offer.Job.Hashes.Configuration = offerDigest(offer.Job.NormalizedConfigurationJson)
	offer.Job.TestSecrets = []*p.TestSecretReference{{Name: "license", SecretId: "b1111111-1111-4111-8111-111111111111", Version: 1}}
	features := []p.ProtocolFeature{1, 3, 7, 9, 10}
	config.EnableTestSecrets = true
	if validateNetworkV2Offer(offer, config, now, 10*time.Minute, features, maximum) == nil {
		t.Fatal("unnegotiated secrets accepted")
	}
	features = append(features, p.ProtocolFeature_PROTOCOL_FEATURE_TEST_SECRETS_V1)
	if rejection := validateNetworkV2Offer(offer, config, now, 10*time.Minute, features, maximum); rejection != nil {
		t.Fatal(rejection)
	}
	config.EnableTestSecrets = false
	if validateNetworkV2Offer(offer, config, now, 10*time.Minute, features, maximum) == nil {
		t.Fatal("disabled secrets accepted")
	}
}
