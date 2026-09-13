package terminalevidence

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

func secretConfigurationJob(t *testing.T, selection any) *runnerv1.JobSpecification {
	t.Helper()
	job := productionJob(t)
	var configuration map[string]any
	if err := json.Unmarshal(job.NormalizedConfigurationJson, &configuration); err != nil {
		t.Fatal(err)
	}
	configuration["tests"].(map[string]any)["secrets"] = selection
	raw, err := canonicalJSON(configuration)
	if err != nil {
		t.Fatal(err)
	}
	job.NormalizedConfigurationJson = raw
	hash := sha256.Sum256(raw)
	job.Hashes.Configuration.Value = hash[:]
	return job
}

// Evidence binds configuration metadata, never secret plaintext. Delivery still
// requires the independently authorized exact lease and selected references.
func TestSecretSelectionCreatesFrozenTerminalContext(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "v1", true: "v2"}[v2], func(t *testing.T) {
			job := secretConfigurationJob(t, map[string]any{"fixture-token": float64(1)})
			build := NewContext
			if v2 {
				build = NewContextV2
			}
			context, err := build(job)
			if err != nil {
				t.Fatalf("released secret selection refused: %v", err)
			}
			if context.requested["configurationSha256"] != digest(job.Hashes.Configuration) {
				t.Fatal("secret selection configuration identity was not frozen")
			}
			changed := secretConfigurationJob(t, map[string]any{"fixture-token": float64(2)})
			changed.Hashes.Configuration = job.Hashes.Configuration
			if _, err := build(changed); err == nil {
				t.Fatal("accepted changed selection under original hash")
			}
		})
	}
}

func TestSecretSelectionSchemaRemainsClosedAndBounded(t *testing.T) {
	oversized := map[string]any{}
	for i := 0; i < 65; i++ {
		oversized["token-"+string(rune('a'+i/26))+string(rune('a'+i%26))] = float64(1)
	}
	for name, selection := range map[string]any{
		"plaintext":          "synthetic-value",
		"zero-version":       map[string]any{"fixture-token": float64(0)},
		"fractional-version": map[string]any{"fixture-token": 1.5},
		"string-value":       map[string]any{"fixture-token": "synthetic-value"},
		"unsafe-name":        map[string]any{"../token": float64(1)},
		"too-many":           oversized,
	} {
		t.Run(name, func(t *testing.T) {
			job := secretConfigurationJob(t, selection)
			if _, err := NewContext(job); err == nil {
				t.Fatal("accepted invalid selection in v1")
			}
			if _, err := NewContextV2(job); err == nil {
				t.Fatal("accepted invalid selection in v2")
			}
		})
	}
}
