package terminalevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"testing"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func productionJob(t *testing.T) *runnerv1.JobSpecification {
	t.Helper()
	raw, err := os.ReadFile("testdata/platform-created-job.json")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(bytes.TrimSuffix(raw, []byte("\n")))
	if hex.EncodeToString(hash[:]) != "435329914a5cb6b7af1ab60b341c88bb5dc8419cf2978a1bd19bf74ec550cc0a" {
		t.Fatal("production fixture identity changed")
	}
	job := new(runnerv1.JobSpecification)
	if err := protojson.Unmarshal(raw, job); err != nil {
		t.Fatal(err)
	}
	// Persisted dispatch templates intentionally have no ephemeral lease binding.
	// Only binding is supplied here; actual producer configuration/hashes remain.
	job.Lease = &runnerv1.LeaseIdentity{JobId: "job-1", ExecutionId: "execution-1", LeaseId: "lease-1"}
	job.Attempt = &runnerv1.AttemptIdentity{AttemptId: "attempt-1", ReleaseCandidateId: "candidate-1", MatrixEntryId: "matrix-1", AttemptNumber: 1}
	return job
}

func TestActualPlatformCreatedJobAndReleasedReference(t *testing.T) {
	job := productionJob(t)
	context, err := NewContext(job)
	if err != nil {
		t.Fatal(err)
	}
	observations := []Observation{
		{Type: "startup-ready", ServerLoaded: true, StabilizationCompleted: true, ServerReady: true, RequirementsSatisfied: true},
		{Type: "plugin-enabled", Name: job.TargetPluginName, Loaded: true, Enabled: false},
		{Type: "clean-shutdown", ShutdownRequested: true, ServerStopped: true, ReportedShutdownRequested: true},
	}
	proof, err := Build(context, "runner-1", observations)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFrozen(proof, job, "runner-1"); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(proof.CanonicalJson, &value); err != nil {
		t.Fatal(err)
	}
	if value["runtime"] != nil || value["completeness"] != "partial" {
		t.Fatal("unmeasured runtime became complete")
	}
	validateReleasedProof(t, context, proof)
	// Mutation of the supplied job cannot alter the already frozen context.
	job.TargetPluginName = "changed"
	job.NormalizedConfigurationJson[0] = '!'
	job.Hashes.Artifact.Value[0] ^= 1
	again, err := Build(context, "runner-1", observations)
	if err != nil || !proto.Equal(proof, again) {
		t.Fatal("context aliases caller job")
	}
}

func validateReleasedProof(t *testing.T, context *Context, proof *runnerv1.ExecutionEvidence) {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(proof.CanonicalJson, &value); err != nil {
		t.Fatal(err)
	}
	assertions := []any{}
	for _, p := range context.planned {
		selector := p.selector
		if selector == nil {
			selector = map[string]string{}
		}
		assertions = append(assertions, map[string]any{"id": p.id, "type": p.kind, "supported": p.supported, "selector": selector})
	}
	sort.Slice(assertions, func(i, j int) bool {
		return assertions[i].(map[string]any)["id"].(string) < assertions[j].(map[string]any)["id"].(string)
	})
	input, _ := json.Marshal(map[string]any{"raw": string(proof.CanonicalJson), "digest": hex.EncodeToString(proof.Digest.Value), "expected": map[string]any{"featureEnabled": true, "wholeMessageBytes": len(proof.CanonicalJson) + 100, "binding": value["binding"], "requested": value["requested"], "assertions": assertions}})
	command := exec.Command("node", "--input-type=module", "-e", `import {validateTerminal} from './testdata/reference.mjs'; let s=''; for await (const c of process.stdin) s+=c; const x=JSON.parse(s); validateTerminal(Buffer.from(x.raw),x.digest,x.expected);`)
	command.Stdin = bytes.NewReader(input)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("released reference rejected actual producer mapping: %v %s", err, output)
	}
}

func TestFrozenProofRejectsIdentityBytesAndUnsupportedClaims(t *testing.T) {
	job := productionJob(t)
	context, err := NewContext(job)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := Build(context, "runner-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*runnerv1.ExecutionEvidence){
		func(p *runnerv1.ExecutionEvidence) { p.CanonicalJson = append(p.CanonicalJson, ' ') },
		func(p *runnerv1.ExecutionEvidence) { p.Digest.Value[0] ^= 1 },
		func(p *runnerv1.ExecutionEvidence) {
			p.CanonicalJson = bytes.Replace(p.CanonicalJson, []byte("partial"), []byte("complete"), 1)
			h := sha256.Sum256(p.CanonicalJson)
			p.Digest.Value = h[:]
		},
	} {
		copy := proto.Clone(proof).(*runnerv1.ExecutionEvidence)
		mutate(copy)
		if ValidateFrozen(copy, job, "runner-1") == nil {
			t.Fatal("mutated proof accepted")
		}
	}
	if ValidateFrozen(proof, job, "runner-2") == nil {
		t.Fatal("runner substitution accepted")
	}
	job.Attempt.AttemptNumber++
	if ValidateFrozen(proof, job, "runner-1") == nil {
		t.Fatal("attempt substitution accepted")
	}
	if _, err := Build(context, "runner-1", []Observation{{Type: "unknown"}}); err == nil {
		t.Fatal("unknown observation accepted")
	}
	if _, err := Build(context, "runner-1", make([]Observation, 257)); err != ErrBounds {
		t.Fatal("count overflow accepted")
	}
}
