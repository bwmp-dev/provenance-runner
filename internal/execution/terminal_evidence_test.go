package execution

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestCollectedNetworkObservationKeepsOpaqueIdentity(t *testing.T) {
	observation := &runtimeidentity.NetworkObservation{}
	prepared := &fakePrepared{collect: func(context.Context) (CollectedOutput, error) {
		return CollectedOutput{MeasuredNetwork: observation}, nil
	}}
	var result Result
	collectPrepared(context.Background(), prepared, time.Second, &result)
	if result.MeasuredNetwork != observation {
		t.Fatal("opaque observation copied or lost")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var restored Result
	if json.Unmarshal(raw, &restored) != nil || restored.MeasuredNetwork != nil {
		t.Fatal("JSON recreated authority")
	}
}

func TestForgedNetworkObservationNeverFallsBackToSnapshot(t *testing.T) {
	raw, err := os.ReadFile("../terminalevidence/testdata/platform-created-job.json")
	if err != nil {
		t.Fatal(err)
	}
	job := new(p.JobSpecification)
	if err := protojson.Unmarshal(raw, job); err != nil {
		t.Fatal(err)
	}
	// The persisted dispatch fixture deliberately omits ephemeral identities.
	job.Lease = &p.LeaseIdentity{JobId: "job-1", ExecutionId: "execution-1", LeaseId: "lease-1"}
	job.Attempt = &p.AttemptIdentity{AttemptId: "attempt-1", ReleaseCandidateId: "candidate-1", MatrixEntryId: "matrix-1", AttemptNumber: 1}
	terminal, err := terminalevidence.NewContextV2(job)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []Result{
		{MeasuredNetwork: &runtimeidentity.NetworkObservation{}},
		{TerminalContext: terminal, MeasuredNetwork: &runtimeidentity.NetworkObservation{}},
		{TerminalContext: terminal, MeasuredNetwork: &runtimeidentity.NetworkObservation{}, MeasuredRuntime: &runtimeidentity.Snapshot{}},
	} {
		if proof, err := value.FreezeTerminalEvidence("fixture-runner"); err == nil || proof != nil {
			t.Fatal("forged or ambiguous observation accepted")
		}
	}
	if proof, err := (Result{}).FreezeTerminalEvidence("fixture-runner"); err != nil || proof != nil {
		t.Fatal("absent evidence changed legacy behavior")
	}
}
