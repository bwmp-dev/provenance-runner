package terminalevidence

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

func modernConfigurationJob(t *testing.T, version, floor string) *runnerv1.JobSpecification {
	t.Helper()
	job := productionJob(t)
	var configuration map[string]any
	if err := json.Unmarshal(job.NormalizedConfigurationJson, &configuration); err != nil {
		t.Fatal(err)
	}
	paper := configuration["paper"].(map[string]any)
	entry := paper["matrix"].([]any)[0].(map[string]any)
	entry["minecraftVersion"], entry["paperBuild"], entry["javaVersion"] = version, float64(74), float64(25)
	paper["recommendations"].(map[string]any)["apiFloor"] = floor
	raw, err := canonicalJSON(configuration)
	if err != nil {
		t.Fatal(err)
	}
	job.NormalizedConfigurationJson = raw
	digest := sha256.Sum256(raw)
	job.Hashes.Configuration.Value = digest[:]
	job.Environment.GameVersion = version
	job.Environment.ServerVersion = version
	job.Environment.ServerBuild = 74
	job.Environment.JavaVersion = "25.0.4.1+1"
	return job
}

func TestModernConfigurationCreatesFrozenTerminalContext(t *testing.T) {
	job := modernConfigurationJob(t, "26.1.2", "26.1")
	context, err := NewContext(job)
	if err != nil {
		t.Fatalf("modern configuration context: %v", err)
	}
	proof, err := Build(context, "runner-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFrozen(proof, job, "runner-1"); err != nil {
		t.Fatal(err)
	}
	// A different valid modern version is still a different frozen request.
	changed := modernConfigurationJob(t, "26.1.3", "26.1")
	if err := ValidateFrozen(proof, changed, "runner-1"); err == nil {
		t.Fatal("accepted changed configuration identity")
	}
}

func TestModernConfigurationRejectsUnsupportedVersionsAndFloor(t *testing.T) {
	for _, tc := range []struct{ version, floor string }{{"26.0", "26.1"}, {"26.01", "26.1"}, {"26.1-rc1", "26.1"}, {"27.1", "26.1"}, {"26.1.2", "26.0"}} {
		if _, err := NewContext(modernConfigurationJob(t, tc.version, tc.floor)); err == nil {
			t.Fatalf("accepted version %s floor %s", tc.version, tc.floor)
		}
	}
}
