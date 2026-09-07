package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type evidenceRemoteProvider struct {
	observed []terminalevidence.Observation
	executed int
}

func (p *evidenceRemoteProvider) Name() string     { return "paper" }
func (p *evidenceRemoteProvider) Identity() string { return "test-only" }
func (p *evidenceRemoteProvider) AdaptJob(j *runnerv1.JobSpecification) (localjob.Job, error) {
	return localjob.Job{SchemaVersion: localjob.SchemaVersion, ID: j.Lease.JobId, Provider: "paper", Environment: json.RawMessage(`{}`), MaxOutputBytes: 1024}, nil
}
func (p *evidenceRemoteProvider) Resolve(context.Context, execution.Request) (execution.Environment, error) {
	return p, nil
}
func (p *evidenceRemoteProvider) Prepare(context.Context) (execution.PreparedEnvironment, error) {
	return p, nil
}
func (p *evidenceRemoteProvider) Execute(context.Context) (execution.ExecutionOutcome, error) {
	p.executed++
	return execution.ExecutionOutcome{}, nil
}
func (p *evidenceRemoteProvider) Collect(context.Context) (execution.CollectedOutput, error) {
	return execution.CollectedOutput{TerminalObservations: p.observed}, nil
}
func (p *evidenceRemoteProvider) Cleanup(context.Context) error { return nil }

func TestConnectedWorkerFreezesContextAndExecutorObservationProjection(t *testing.T) {
	raw, err := os.ReadFile("../../internal/terminalevidence/testdata/platform-created-job.json")
	if err != nil {
		t.Fatal(err)
	}
	job := new(runnerv1.JobSpecification)
	if err := protojson.Unmarshal(raw, job); err != nil {
		t.Fatal(err)
	}
	job.Lease = &runnerv1.LeaseIdentity{LeaseId: "lease-1", JobId: "job-1", ExecutionId: "execution-1"}
	job.Attempt = &runnerv1.AttemptIdentity{AttemptId: "attempt-1", ReleaseCandidateId: "candidate-1", MatrixEntryId: "matrix-1", AttemptNumber: 1}
	original := proto.Clone(job).(*runnerv1.JobSpecification)
	provider := &evidenceRemoteProvider{observed: []terminalevidence.Observation{{Type: "plugin-enabled", Name: job.TargetPluginName, Loaded: true, Enabled: true}}}
	registry, err := execution.NewRegistry(provider)
	if err != nil {
		t.Fatal(err)
	}
	worker := &connectedWorker{registry: registry, adapter: provider}
	result := worker.Execute(context.Background(), job, nil)
	if !result.Passed() || provider.executed != 1 || result.TerminalContext == nil || len(result.TerminalObservations) != 1 {
		t.Fatalf("remote result lost internal projection: %s", result.Classification)
	}
	job.NormalizedConfigurationJson[0] = '!'
	provider.observed[0].Enabled = false
	proof, err := terminalevidence.Build(result.TerminalContext, "runner-1", result.TerminalObservations)
	if err != nil {
		t.Fatal(err)
	}
	if err := terminalevidence.ValidateFrozen(proof, original, "runner-1"); err != nil {
		t.Fatal(err)
	}
	if !result.TerminalObservations[0].Enabled {
		t.Fatal("executor observation aliases provider")
	}
	public, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("TerminalContext"), []byte("TerminalObservations"), []byte("plugin-enabled")} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("internal evidence changed public result JSON")
		}
	}
	invalid := worker.Execute(context.Background(), job, nil)
	if invalid.Failure == nil || invalid.Failure.Code != "terminal_evidence_context_invalid" || provider.executed != 1 {
		t.Fatal("invalid context did not fail before execution")
	}
}
