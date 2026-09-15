//go:build linux

package measuredservice

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func fixtureDigest(raw []byte) *p.Digest {
	digest := sha256.Sum256(raw)
	return &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}
}

func serviceFixtureJob(t *testing.T, java, prepared []byte) (*paper.RuntimeSource, paper.SignedRuntime, *p.JobSpecification) {
	t.Helper()
	// Public synthetic test key; never accepted by any production source.
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{57}, 32))
	source, err := paper.NewRuntimeSource("https://api.example", hex.EncodeToString(key.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	catalog := paper.AlphaCatalog()
	pin := func(raw []byte, name string) paper.ArtifactPin {
		digest := sha256.Sum256(raw)
		return paper.ArtifactPin{Filename: name, SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(raw))}
	}
	catalog.Java.Artifact = pin(java, "java.tar.gz")
	catalog.Java.ArchiveRoot = "jre"
	catalog.Java.MaximumExpandedBytes = 64 << 20
	catalog.Paper.Artifact = pin([]byte("synthetic paper"), "paper.jar")
	catalog.PreparedRuntime = paper.ArchivePin{Artifact: pin(prepared, "prepared-runtime.tar.gz"), MaximumExpandedBytes: 1 << 20}
	identity := sha256.Sum256([]byte(fmt.Sprintf("provenance.paper-runtime/v1\n%s\x00%d\x00%s\x00%s\x00%s\x00linux\x00amd64", catalog.Paper.GameVersion, catalog.Paper.Build, catalog.Paper.Artifact.SHA256, catalog.Java.Distribution, catalog.Java.Version)))
	id := hex.EncodeToString(identity[:])
	catalog.EnvironmentID = "paper-runtime-" + id
	for _, pin := range []*paper.ArtifactPin{&catalog.Java.Artifact, &catalog.Paper.Artifact, &catalog.Probe, &catalog.PreparedRuntime.Artifact} {
		pin.URI = source.Origin + "/v1/paper-runtime-assets/" + pin.SHA256 + "/" + pin.Filename
	}
	manifestBytes, err := json.Marshal(struct {
		RuntimeID string        `json:"runtimeId"`
		Catalog   paper.Catalog `json:"catalog"`
	}{id, catalog})
	if err != nil {
		t.Fatal(err)
	}
	manifest := paper.SignedRuntime{Payload: manifestBytes, Signature: ed25519.Sign(key, append([]byte("provenance.paper-runtime/v1\n"), manifestBytes...))}
	normalized, err := json.Marshal(map[string]any{
		"apiVersion": "provenance.dev/v1", "project": map[string]any{"id": "service-fixture", "name": "ServiceFixture"},
		"artifact":     map[string]any{"id": "service-fixture", "path": "build/service.jar", "version": "1.0.0"},
		"dependencies": []any{},
		"tests":        map[string]any{"startup": map[string]any{"timeoutSeconds": 10, "stabilizationSeconds": 1, "requirePluginEnabled": true, "shutdownTimeoutSeconds": 1, "requireCleanShutdown": true}, "console": []map[string]any{{"id": "service-command", "command": "help", "timeoutSeconds": 1, "assertions": []map[string]any{{"stream": "combined", "operator": "contains", "pattern": "ROOT_SERVICE_OK", "match": "present", "minimumOccurrences": 1}}}}},
		"resources":    map[string]any{"cpuCores": 1, "memoryMiB": 128, "diskMiB": 256, "processes": 64, "wallTimeoutSeconds": 20, "logBytes": 1 << 20},
	})
	if err != nil {
		t.Fatal(err)
	}
	job := &p.JobSpecification{
		TargetPluginName:            "ServiceFixture",
		Lease:                       &p.LeaseIdentity{JobId: "a1111111-1111-4111-8111-111111111111", LeaseId: "a2222222-2222-4222-8222-222222222222", ExecutionId: "a3333333-3333-4333-8333-333333333333", ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))},
		Attempt:                     &p.AttemptIdentity{AttemptId: "a4444444-4444-4444-8444-444444444444", ReleaseCandidateId: "a5555555-5555-4555-8555-555555555555", MatrixEntryId: "a6666666-6666-4666-8666-666666666666", AttemptNumber: 1},
		Environment:                 &p.ResolvedEnvironment{Provider: p.ServerProvider_SERVER_PROVIDER_PAPER, GameVersion: catalog.Paper.GameVersion, ServerVersion: catalog.Paper.GameVersion, ServerBuild: catalog.Paper.Build, JavaDistribution: catalog.Java.Distribution, JavaVersion: catalog.Java.Version, OperatingSystem: p.OperatingSystem_OPERATING_SYSTEM_LINUX, Architecture: p.Architecture_ARCHITECTURE_AMD64, ServerBinary: fixtureDigest([]byte("synthetic paper"))},
		Artifact:                    &p.ObjectDownload{Filename: "target.jar", Digest: fixtureDigest([]byte("synthetic target")), SizeBytes: int64(len("synthetic target"))},
		Hashes:                      &p.JobHashes{Artifact: fixtureDigest([]byte("synthetic target")), Configuration: fixtureDigest(normalized)},
		NormalizedConfigurationJson: normalized,
		EffectivePolicy:             &p.EffectivePolicy{Sandbox: p.SandboxKind_SANDBOX_KIND_GVISOR, Requirement: p.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED, Resources: &p.ResourceLimits{CpuMillis: 1000, MemoryBytes: 128 << 20, DiskBytes: 256 << 20, ProcessCount: 64}, PreparationTimeout: durationpb.New(20 * time.Second), ExecutionTimeout: durationpb.New(20 * time.Second), GracefulShutdownTimeout: durationpb.New(time.Second), NetworkV2: &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_ALLOWLIST, MaximumConnections: 8, MaximumBytesPerSecond: 65536, Permissions: []*p.NetworkPermissionV2{{Hostname: "example.com", Port: 443, Transport: p.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP}}}},
	}
	digest, err := np.EffectivePolicyV2SHA256(job.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Policy = &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}
	return source, manifest, job
}

func TestServiceFixtureUsesClosedSignedAdmission(t *testing.T) {
	source, manifest, job := serviceFixtureJob(t, []byte("synthetic java archive"), []byte("synthetic prepared archive"))
	raw, err := paper.EncodeMeasuredRequest(job, manifest)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := source.PrepareMeasuredRequest(raw, 64<<20)
	if err != nil || len(plan.Inputs()) != 6 {
		t.Fatal("signed fixture admission", err)
	}
}
