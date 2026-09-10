package paper

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestPaperCollectionToVersionedLiteralProof(t *testing.T) {
	for _, passed := range []bool{false, true} {
		for _, v2 := range []bool{false, true} {
			raw, err := os.ReadFile("../../terminalevidence/testdata/platform-created-job.json")
			if err != nil {
				t.Fatal(err)
			}
			job := new(runnerv1.JobSpecification)
			if protojson.Unmarshal(raw, job) != nil {
				t.Fatal("job fixture")
			}
			job.Lease = &runnerv1.LeaseIdentity{JobId: "job-1", ExecutionId: "execution-1", LeaseId: "lease-1"}
			job.Attempt = &runnerv1.AttemptIdentity{AttemptId: "attempt-1", ReleaseCandidateId: "candidate-1", MatrixEntryId: "matrix-1", AttemptNumber: 1}
			job.TargetPluginName = "SuccessFixture"
			var config map[string]any
			if json.Unmarshal(job.NormalizedConfigurationJson, &config) != nil {
				t.Fatal("config fixture")
			}
			config["tests"].(map[string]any)["console"] = []any{map[string]any{"id": "version-command", "command": "version", "timeoutSeconds": 10, "assertions": []any{map[string]any{"operator": "contains", "stream": "combined", "pattern": "ok", "match": "present"}}}}
			job.NormalizedConfigurationJson, err = json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(job.NormalizedConfigurationJson)
			job.Hashes.Configuration.Value = h[:]
			builder, validate := terminalevidence.NewContext, terminalevidence.ValidateFrozen
			if v2 {
				builder, validate = terminalevidence.NewContextV2, terminalevidence.ValidateFrozenV2
			}
			proofContext, err := builder(job)
			if err != nil {
				t.Fatal(err)
			}
			fixture := commandProbeOutput(passed)
			prepared := &preparedEnvironment{terminalEvidenceV2: v2, delegate: &fakePrepared{output: &fixture}, plan: testPlan{TargetPlugin: job.TargetPluginName, Console: []consoleCommandTest{{ID: "version-command", Command: "version", TimeoutSeconds: 10, Assertions: []commandAssertion{{Operator: "contains", Stream: "combined", Pattern: "ok", Match: "present"}}}}}}
			output, err := prepared.Collect(context.Background())
			if (err == nil) != passed {
				t.Fatal("collection classification changed", err)
			}
			// Synthetic execution-bound snapshot for composition only; no host measurement claim.
			measured := &runtimeidentity.Snapshot{RunnerVersion: "fixture", RunnerExecutableSHA256: strings.Repeat("1", 64), SandboxKind: "gvisor", SandboxVersion: "fixture", SandboxExecutableSHA256: strings.Repeat("2", 64), NetworkMode: "none", RootFS: runtimeidentity.RootFS{Format: "squashfs-image-sha256/v1", SHA256: strings.Repeat("3", 64)}}
			proof, err := terminalevidence.Build(proofContext, "runner-1", output.TerminalObservations, measured)
			if err != nil || validate(proof, job, "runner-1") != nil {
				t.Fatal("collection proof failed saved-byte validation", err)
			}
			var value map[string]any
			if json.Unmarshal(proof.CanonicalJson, &value) != nil {
				t.Fatal("proof JSON")
			}
			if (value["completeness"] == "complete") != v2 {
				t.Fatal("v1 history promoted or v2 literal coverage missing")
			}
			found := false
			for _, item := range value["assertions"].([]any) {
				a := item.(map[string]any)
				if a["type"] != "console-contains" {
					continue
				}
				found = true
				if a["id"] != "console-contains:version-command:1" || (a["outcome"] == "passed") != passed {
					t.Fatal("literal outcome mapping changed")
				}
			}
			if found != v2 {
				t.Fatal("version literal projection mismatch")
			}
		}
	}
}
