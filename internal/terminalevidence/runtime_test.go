package terminalevidence

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	"google.golang.org/protobuf/encoding/protojson"
)

func measuredFixture() runtimeidentity.Snapshot {
	return runtimeidentity.Snapshot{RunnerVersion: "0.1.0", RunnerExecutableSHA256: strings.Repeat("1", 64), SandboxKind: "gvisor", SandboxVersion: "release-20260817.0", SandboxExecutableSHA256: strings.Repeat("2", 64), NetworkMode: "none", RootFS: runtimeidentity.RootFS{Format: "squashfs-image-sha256/v1", SHA256: strings.Repeat("3", 64)}}
}

func TestMeasuredRuntimeCompletenessAndHistoricalReplay(t *testing.T) {
	job := productionJob(t)
	c, err := NewContext(job)
	if err != nil {
		t.Fatal(err)
	}
	runtime := measuredFixture()
	observations := []Observation{{Type: "startup-ready", ServerLoaded: true, StabilizationCompleted: true, ServerReady: true, RequirementsSatisfied: false}, {Type: "plugin-enabled", Name: job.TargetPluginName, Loaded: true, Enabled: false}, {Type: "clean-shutdown", ShutdownRequested: true, ServerStopped: true, ReportedShutdownRequested: true}}
	proof, err := Build(c, "runner-1", observations, &runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(proof.CanonicalJson, []byte(`"completeness":"complete"`)) || !bytes.Contains(proof.CanonicalJson, []byte(`"outcome":"failed"`)) {
		t.Fatal("complete incorrectly means passing")
	}
	if err := ValidateFrozen(proof, job, "runner-1"); err != nil {
		t.Fatal(err)
	}
	validateReleasedProof(t, c, proof)
	// Optional local cross-consumer diagnostic emits only the synthetic frozen
	// fixture, never job/provider runtime inputs or credentials.
	if os.Getenv("PROVENANCE_RUNTIME_PARITY_DIAGNOSTIC") == "1" {
		jobJSON, err := protojson.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		proofJSON, err := protojson.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := json.Marshal(map[string]json.RawMessage{"Job": jobJSON, "Proof": proofJSON})
		if err != nil {
			t.Fatal(err)
		}
		t.Log("RUNTIME_PARITY=" + string(pair))
	}
	value, err := parseJSON(proof.CanonicalJson)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSON(value)
	if err != nil || !bytes.Equal(canonical, proof.CanonicalJson) {
		t.Fatal("runtime is not canonical")
	}
	runtime.RootFS.SHA256 = strings.Repeat("4", 64)
	if err := ValidateFrozen(proof, job, "runner-1"); err != nil {
		t.Fatal("historical proof consulted replacement runtime")
	}
	incomplete, err := Build(c, "runner-1", observations[:1], &runtime)
	if err != nil || !bytes.Contains(incomplete.CanonicalJson, []byte(`"completeness":"partial"`)) {
		t.Fatal("missing observations became complete")
	}
	legacy, err := Build(c, "runner-1", observations)
	if err != nil || !bytes.Contains(legacy.CanonicalJson, []byte(`"runtime":null`)) {
		t.Fatal("legacy null runtime changed")
	}
	if ValidateFrozen(legacy, job, "runner-1") != nil {
		t.Fatal("legacy frozen proof rejected")
	}
	runtime.NetworkMode = "restricted"
	if _, err := Build(c, "runner-1", observations, &runtime); err == nil {
		t.Fatal("unimplemented network enforcement claimed")
	}
}
