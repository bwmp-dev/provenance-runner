//go:build linux

package gvisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Only disposable synthetic evidence input; no Paper/plugin success is claimed.
func measuredEvidenceFixture(t *testing.T, job *p.JobSpecification) *terminalevidence.Context {
	t.Helper()
	raw, err := os.ReadFile("/repo/internal/terminalevidence/testdata/platform-created-job.json")
	hash := sha256.Sum256(bytes.TrimSuffix(raw, []byte("\n")))
	if err != nil || hex.EncodeToString(hash[:]) != "435329914a5cb6b7af1ab60b341c88bb5dc8419cf2978a1bd19bf74ec550cc0a" {
		t.Fatal("evidence fixture identity")
	}
	base := new(p.JobSpecification)
	if protojson.Unmarshal(raw, base) != nil {
		t.Fatal("evidence fixture decode")
	}
	base.Lease, base.Attempt, base.EffectivePolicy, base.Hashes.Policy = job.Lease, job.Attempt, job.EffectivePolicy, job.Hashes.Policy
	var config map[string]any
	if json.Unmarshal(base.NormalizedConfigurationJson, &config) != nil {
		t.Fatal("configuration fixture")
	}
	config["apiVersion"] = "provenance.dev/v2"
	config["network"] = map[string]any{"mode": "allowlist", "maximumConnections": 16, "maximumBytesPerSecond": 65536, "permissions": []any{
		map[string]any{"hostname": "fixture.example.com", "port": 8080, "transport": "tcp"},
		map[string]any{"hostname": "fixture.example.com", "port": 8081, "transport": "udp"},
	}}
	base.NormalizedConfigurationJson, err = json.Marshal(config)
	if err != nil {
		t.Fatal("configuration fixture encoding")
	}
	hash = sha256.Sum256(base.NormalizedConfigurationJson)
	base.Hashes.Configuration.Value = hash[:]
	proto.Reset(job)
	proto.Merge(job, base)
	c, err := terminalevidence.NewContextV2(job)
	if err != nil {
		t.Fatal("network evidence context", err)
	}
	return c
}
