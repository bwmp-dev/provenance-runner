package paper

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func measuredPlanFixture(t *testing.T) (*RuntimeSource, SignedRuntime, *p.JobSpecification) {
	t.Helper()
	source, manifest, catalog := automaticFixture(t, "https://api.example")
	job := validRemoteSpecification(t, "https://download.example", map[string][]byte{"/target": []byte("target"), "/dependency": []byte("dependency")})
	job.Environment = exactRemoteEnvironment(t, catalog)
	job.Lease = &p.LeaseIdentity{JobId: "11111111-1111-4111-8111-111111111111", LeaseId: "22222222-2222-4222-8222-222222222222", ExecutionId: "33333333-3333-4333-8333-333333333333", ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}
	job.Attempt = &p.AttemptIdentity{AttemptId: "44444444-4444-4444-8444-444444444444", ReleaseCandidateId: "55555555-5555-4555-8555-555555555555", MatrixEntryId: "66666666-6666-4666-8666-666666666666", AttemptNumber: 1}
	job.EffectivePolicy.Network = nil
	job.EffectivePolicy.Requirement = p.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED
	job.EffectivePolicy.NetworkV2 = &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_ALLOWLIST, MaximumConnections: 8, MaximumBytesPerSecond: 65536, Permissions: []*p.NetworkPermissionV2{{Hostname: "example.com", Port: 443, Transport: p.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP}}}
	digest, err := np.EffectivePolicyV2SHA256(job.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Policy = &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}
	return source, manifest, job
}

func TestMeasuredInputPlanDerivedRolesAndCopies(t *testing.T) {
	source, manifest, job := measuredPlanFixture(t)
	before := proto.Clone(job)
	// No network client is needed; this operation verifies the received signature.
	source.Client = nil
	plan, err := source.DeriveMeasuredInputPlan(job, manifest, 64<<30)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(before, job) || !plan.Matches(job) {
		t.Fatal("job mutated or binding lost")
	}
	layout := plan.RuntimeLayout()
	if layout.JavaArchiveRoot == "" || layout.JavaMaximumExpandedBytes == 0 || layout.PreparedMaximumExpandedBytes == 0 {
		t.Fatal("signed archive limits lost")
	}
	layout.JavaArchiveRoot = "changed"
	if plan.RuntimeLayout().JavaArchiveRoot == layout.JavaArchiveRoot {
		t.Fatal("mutable runtime layout escaped")
	}
	inputs := plan.Inputs()
	names := []string{"java.tar.gz", "paper.jar", "provenance-probe.jar", "prepared-runtime.tar.gz", "target.jar", "dependency-000.jar", "provenance-test-plan.json"}
	if len(inputs) != len(names) {
		t.Fatal("wrong role count")
	}
	for i, name := range names {
		if inputs[i].Name != name {
			t.Fatal("caller filename used as role")
		}
	}
	if inputs[4].SHA256 != sha256.Sum256([]byte("target")) || inputs[5].SHA256 != sha256.Sum256([]byte("dependency")) || inputs[6].SHA256 != sha256.Sum256(plan.ProbePlan()) {
		t.Fatal("derived digest mismatch")
	}
	inputs[0].Name = "changed"
	probe := plan.ProbePlan()
	probe[0] = 'X'
	if plan.Inputs()[0].Name != names[0] || bytes.Equal(probe, plan.ProbePlan()) {
		t.Fatal("mutable plan escaped")
	}
	job.Artifact.SizeBytes++
	if plan.Matches(job) {
		t.Fatal("changed job retained binding")
	}
}

func TestMeasuredInputPlanRejectsIdentityAndInventoryChanges(t *testing.T) {
	for name, mutate := range map[string]func(*p.JobSpecification){
		"artifact hash": func(j *p.JobSpecification) {
			j.Artifact.Digest = proto.Clone(j.Artifact.Digest).(*p.Digest)
			j.Artifact.Digest.Value[0] ^= 1
		},
		"configuration": func(j *p.JobSpecification) {
			j.NormalizedConfigurationJson = append(j.NormalizedConfigurationJson, ' ')
		},
		"policy":         func(j *p.JobSpecification) { j.EffectivePolicy.Resources.MemoryBytes++ },
		"environment":    func(j *p.JobSpecification) { j.Environment.ServerBuild++ },
		"unknown job":    func(j *p.JobSpecification) { j.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01}) },
		"unknown object": func(j *p.JobSpecification) { j.Artifact.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01}) },
		"missing hash":   func(j *p.JobSpecification) { j.Hashes.Dependencies = nil },
		"duplicate dependency": func(j *p.JobSpecification) {
			j.Dependencies = append(j.Dependencies, proto.Clone(j.Dependencies[0]).(*p.DependencyInput))
		},
		"filename":            func(j *p.JobSpecification) { j.Artifact.Filename = "../target.jar" },
		"dependency filename": func(j *p.JobSpecification) { j.Dependencies[0].Object.Filename = "different.jar" },
		"plugin collision":    func(j *p.JobSpecification) { j.Dependencies[0].PluginName = j.TargetPluginName },
		"missing required":    func(j *p.JobSpecification) { j.Dependencies = nil; j.Hashes.Dependencies = nil },
		"size":                func(j *p.JobSpecification) { j.Artifact.SizeBytes = 0 },
		"normalized duplicate": func(j *p.JobSpecification) {
			var v map[string]any
			_ = json.Unmarshal(j.NormalizedConfigurationJson, &v)
			deps := v["dependencies"].([]any)
			v["dependencies"] = append(deps, deps[0])
			j.NormalizedConfigurationJson, _ = json.Marshal(v)
			j.Hashes.Configuration = protoDigest(j.NormalizedConfigurationJson)
		},
	} {
		t.Run(name, func(t *testing.T) {
			source, manifest, job := measuredPlanFixture(t)
			mutate(job)
			if plan, err := source.DeriveMeasuredInputPlan(job, manifest, 64<<30); plan != nil || err == nil {
				t.Fatal("malformed identity accepted")
			}
		})
	}
}

func TestMeasuredInputPlanSignatureAndAggregateBounds(t *testing.T) {
	source, manifest, job := measuredPlanFixture(t)
	plan, err := source.DeriveMeasuredInputPlan(job, manifest, 64<<30)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, input := range plan.Inputs() {
		total += input.SizeBytes
	}
	if _, err := source.DeriveMeasuredInputPlan(job, manifest, total); err != nil {
		t.Fatal("exact aggregate refused", err)
	}
	for _, maximum := range []uint64{0, total - 1, 64<<30 + 1} {
		if _, err := source.DeriveMeasuredInputPlan(job, manifest, maximum); err == nil {
			t.Fatal("aggregate bound ignored")
		}
	}
	manifest.Signature[0] ^= 1
	if _, err := source.DeriveMeasuredInputPlan(job, manifest, 64<<30); err == nil {
		t.Fatal("signature ignored")
	}
	var absent *RuntimeSource
	if _, err := absent.DeriveMeasuredInputPlan(job, manifest, 64<<30); err == nil {
		t.Fatal("missing source")
	}
	var missing *MeasuredInputPlan
	if missing.Matches(job) || missing.Inputs() != nil || missing.ProbePlan() != nil {
		t.Fatal("missing plan accepted")
	}
}
