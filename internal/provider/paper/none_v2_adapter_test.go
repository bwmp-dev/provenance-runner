package paper

import (
	"encoding/json"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func noneV2Fixture(t *testing.T, origin string, payloads map[string][]byte) *p.JobSpecification {
	t.Helper()
	job := validRemoteSpecification(t, origin, payloads)
	job.Lease = &p.LeaseIdentity{JobId: "11111111-1111-4111-8111-111111111111", LeaseId: "22222222-2222-4222-8222-222222222222", ExecutionId: "33333333-3333-4333-8333-333333333333", ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}
	job.Attempt = &p.AttemptIdentity{AttemptId: "44444444-4444-4444-8444-444444444444", ReleaseCandidateId: "55555555-5555-4555-8555-555555555555", MatrixEntryId: "66666666-6666-4666-8666-666666666666", AttemptNumber: 1}
	job.EffectivePolicy.Network = nil
	job.EffectivePolicy.NetworkV2 = &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_NONE}
	job.EffectivePolicy.Requirement = p.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED
	policy, err := np.EffectivePolicyV2SHA256(job.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Policy = &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: policy[:]}
	environment, err := proto.MarshalOptions{Deterministic: true}.Marshal(job.Environment)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Environment = protoDigest(environment)
	var config map[string]any
	if json.Unmarshal(job.NormalizedConfigurationJson, &config) != nil {
		t.Fatal("fixture")
	}
	config["apiVersion"] = "provenance.dev/v2"
	config["network"] = map[string]any{"mode": "none", "permissions": []any{}, "maximumConnections": 0, "maximumBytesPerSecond": 0}
	config["release"] = map[string]any{"mode": "test-only", "targets": []any{}}
	config["paper"] = map[string]any{
		"matrix":          []any{map[string]any{"id": "service-paper", "minecraftVersion": "1.21.8", "paperBuild": 60, "javaVersion": 21, "policy": "required"}},
		"recommendations": map[string]any{"apiFloor": "1.21.8", "enabled": false, "newVersions": "informational"},
		"gatePolicy":      map[string]any{"informationalFailure": "report", "infrastructureFailure": "retry", "maxInfrastructureRetries": 2, "requiredFailure": "block"},
	}
	job.NormalizedConfigurationJson, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Configuration = protoDigest(job.NormalizedConfigurationJson)
	if _, err := terminalevidence.NewContextV2(job); err != nil {
		t.Fatal("closed none-v2 fixture", err)
	}
	return job
}

func TestNoneV2AdapterPreservesOriginalWireIdentity(t *testing.T) {
	provider, server, payloads := validationTestProvider(t)
	job := noneV2Fixture(t, server.URL, payloads)
	before := proto.Clone(job)
	local, err := provider.AdaptNoNetworkV2(job)
	if err != nil || local.ID != job.Lease.JobId || !proto.Equal(before, job) {
		t.Fatal("explicit no-network v2 adaptation", err)
	}
	if _, err := provider.AdaptJob(job); err == nil {
		t.Fatal("legacy admission widened")
	}
	context, err := terminalevidence.NewContextV2(job)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := terminalevidence.Build(context, "fixture-runner", nil)
	if err != nil || terminalevidence.ValidateFrozenV2(frozen, job, "fixture-runner") != nil {
		t.Fatal("original v2 evidence binding")
	}
}

func TestNoneV2AdapterCannotDowngradeNetworkOrLoseSecrets(t *testing.T) {
	provider, server, payloads := validationTestProvider(t)
	for _, mode := range []string{"mixed", "allowlist", "restricted", "bad-hash", "missing-selection", "measured-only"} {
		t.Run(mode, func(t *testing.T) {
			job := noneV2Fixture(t, server.URL, payloads)
			copyProvider := *provider
			switch mode {
			case "mixed":
				job.EffectivePolicy.Network = &p.NetworkPolicy{Mode: p.NetworkMode_NETWORK_MODE_NONE}
			case "allowlist":
				job.EffectivePolicy.NetworkV2.Mode = p.NetworkMode_NETWORK_MODE_ALLOWLIST
			case "restricted":
				job.EffectivePolicy.NetworkV2.Mode = p.NetworkMode_NETWORK_MODE_RESTRICTED
			case "bad-hash":
				job.Hashes.Configuration.Value[0] ^= 1
			case "missing-selection":
				job.TestSecrets = []*p.TestSecretReference{{Name: "license", SecretId: "b1111111-1111-4111-8111-111111111111", Version: 1}}
			case "measured-only":
				copyProvider.measuredOnly = true
			}
			before := proto.Clone(job)
			if _, err := copyProvider.AdaptNoNetworkV2(job); err == nil || !proto.Equal(before, job) {
				t.Fatal("invalid or broadened job admitted")
			}
		})
	}
}
