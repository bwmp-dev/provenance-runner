//go:build linux

package runtimeidentity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRootObservationRequiresSealedSourceAndAuthenticatedReceipt(t *testing.T) {
	if raw, err := EncodeRootObservation(nil, &NetworkObservation{observed: true}); raw != nil || err == nil {
		t.Fatal("unbound observation exported")
	}
	var decoded controlchannel.RootObservationPacket
	if json.Unmarshal([]byte(`{"authenticated":true,"payload":"forged"}`), &decoded) != nil {
		t.Fatal("fixture JSON")
	}
	for _, packet := range []*controlchannel.RootObservationPacket{nil, &decoded} {
		if observed, err := ImportRootObservation(&p.JobSpecification{}, packet); observed != nil || err == nil {
			t.Fatal("unbound forged receipt imported")
		}
	}
}

func proxyJobFixture(t *testing.T) *p.JobSpecification {
	t.Helper()
	policy := &p.EffectivePolicy{Sandbox: p.SandboxKind_SANDBOX_KIND_GVISOR, Requirement: p.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED,
		NetworkV2: &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_ALLOWLIST, MaximumConnections: 8, MaximumBytesPerSecond: 65536, Permissions: []*p.NetworkPermissionV2{{Hostname: "example.com", Port: 443, Transport: p.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP}}},
		Resources: &p.ResourceLimits{CpuMillis: 1000, MemoryBytes: 1 << 30, DiskBytes: 2 << 30, ProcessCount: 64}, PreparationTimeout: durationpb.New(time.Minute), ExecutionTimeout: durationpb.New(time.Minute), GracefulShutdownTimeout: durationpb.New(30 * time.Second)}
	hash, err := np.EffectivePolicyV2SHA256(policy)
	if err != nil {
		t.Fatal(err)
	}
	return &p.JobSpecification{Lease: &p.LeaseIdentity{JobId: "11111111-1111-4111-8111-111111111111", LeaseId: "22222222-2222-4222-8222-222222222222", ExecutionId: "33333333-3333-4333-8333-333333333333", ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))},
		Attempt: &p.AttemptIdentity{AttemptId: "44444444-4444-4444-8444-444444444444", ReleaseCandidateId: "55555555-5555-4555-8555-555555555555", MatrixEntryId: "66666666-6666-4666-8666-666666666666", AttemptNumber: 1}, EffectivePolicy: policy, Hashes: &p.JobHashes{Policy: &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: hash[:]}}}
}

func TestRootObservationExportBindsCompleteJobAndRequiresReceipt(t *testing.T) {
	job := proxyJobFixture(t)
	hash, err := networkObservationJobHash(job)
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic private state tests codec guards only; actual kernel observation
	// and authenticated non-root import are exercised in disposable acceptance.
	observed := &NetworkObservation{jobSHA256: hash, observed: true, lease: proto.Clone(job.Lease).(*p.LeaseIdentity), attempt: proto.Clone(job.Attempt).(*p.AttemptIdentity), hashes: proto.Clone(job.Hashes).(*p.JobHashes),
		snapshot: Snapshot{RunnerVersion: "0.1.0", RunnerExecutableSHA256: strings.Repeat("a", 64), SandboxKind: "gvisor", SandboxVersion: "release-test", SandboxExecutableSHA256: strings.Repeat("b", 64), NetworkMode: "allowlist", RootFS: RootFS{Format: "squashfs-image-sha256/v1", SHA256: strings.Repeat("c", 64)}}}
	if raw, err := EncodeRootObservation(job, observed); err != nil || len(raw) < 36 {
		t.Fatal("synthetic bound export", err)
	}
	changed := proto.Clone(job).(*p.JobSpecification)
	changed.TargetPluginName = "changed"
	if raw, err := EncodeRootObservation(changed, observed); err == nil || raw != nil {
		t.Fatal("same lease/hash but different full job exported")
	}
	if got, err := ImportRootObservation(job, new(controlchannel.RootObservationPacket)); got != nil || err == nil {
		t.Fatal("valid job accepted forged receipt")
	}
	observed.snapshot.NetworkMode = "restricted"
	if raw, err := EncodeRootObservation(job, observed); err == nil || raw != nil {
		t.Fatal("mismatched requested network mode exported")
	}
}
