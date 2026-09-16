//go:build linux

package measuredservice

import (
	"encoding/json"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

func TestSecretSelectionRequiresExplicitAdmissionAndExactMetadata(t *testing.T) {
	for _, mode := range []string{"valid", "missing-reference", "wrong-version", "duplicate-reference", "wrong-name"} {
		t.Run(mode, func(t *testing.T) {
			source, manifest, job := serviceFixtureJob(t, []byte("java"), []byte("prepared"))
			var config map[string]any
			if json.Unmarshal(job.NormalizedConfigurationJson, &config) != nil {
				t.Fatal("config")
			}
			config["tests"].(map[string]any)["secrets"] = map[string]uint64{"license": 1}
			var err error
			job.NormalizedConfigurationJson, err = json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			job.Hashes.Configuration = fixtureDigest(job.NormalizedConfigurationJson)
			job.TestSecrets = []*p.TestSecretReference{{Name: "license", SecretId: "b1111111-1111-4111-8111-111111111111", Version: 1}}
			switch mode {
			case "missing-reference":
				job.TestSecrets = nil
			case "wrong-version":
				job.TestSecrets[0].Version = 2
			case "duplicate-reference":
				job.TestSecrets = append(job.TestSecrets, job.TestSecrets[0])
			case "wrong-name":
				job.TestSecrets[0].Name = "other"
			}
			raw, err := paper.EncodeMeasuredRequest(job, manifest)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := source.PrepareMeasuredRequestWithSecrets(raw, 64<<20)
			if mode == "valid" {
				if err != nil || plan == nil || len(plan.Job().TestSecrets) != 1 {
					t.Fatal("valid explicit selection", err)
				}
				if value, err := source.PrepareMeasuredRequest(raw, 64<<20); err == nil || value != nil {
					t.Fatal("default admission accepted selected secrets")
				}
			} else if err == nil || plan != nil {
				t.Fatal("mismatched metadata admitted")
			}
		})
	}
}

func TestSecretRootConfigurationIsOptionalButExplicit(t *testing.T) {
	config := fixtureDaemonConfig(t)
	config.SecretRoot = "/run/provenance-secrets"
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeDaemonConfig(raw)
	if err != nil || got == nil || got.SecretRoot != config.SecretRoot {
		t.Fatal("explicit secret root", err)
	}
}
