package terminalevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func networkContextJob(t *testing.T) *runnerv1.JobSpecification {
	t.Helper()
	job := productionJob(t)
	var document map[string]any
	if json.Unmarshal(job.NormalizedConfigurationJson, &document) != nil {
		t.Fatal("fixture")
	}
	document["apiVersion"] = "provenance.dev/v2"
	// Deliberately not wire-sorted: configuration array identity is preserved.
	document["network"] = map[string]any{"mode": "allowlist", "maximumConnections": 8, "maximumBytesPerSecond": 65536, "permissions": []any{map[string]any{"hostname": "b.example", "port": 8443, "transport": "udp"}, map[string]any{"hostname": "a.example", "port": 443, "transport": "tcp"}}}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonicalJSON(parsed)
	if err != nil {
		t.Fatal(err)
	}
	job.NormalizedConfigurationJson = raw
	hash := sha256.Sum256(raw)
	job.Hashes.Configuration.Value = hash[:]
	job.EffectivePolicy.Network = nil
	job.EffectivePolicy.NetworkV2 = &runnerv1.NetworkPolicyV2{Mode: runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST, MaximumConnections: 4, MaximumBytesPerSecond: 32768, Permissions: []*runnerv1.NetworkPermissionV2{{Hostname: "a.example", Port: 443, Transport: runnerv1.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP}}}
	setNetworkContextPolicyHash(t, job)
	return job
}

func setNetworkContextPolicyHash(t *testing.T, job *runnerv1.JobSpecification) {
	t.Helper()
	hash, err := networkpolicy.EffectivePolicyV2SHA256(job.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Policy.Value = hash[:]
}

func TestNetworkV2TerminalContextPreservesIdentityAndRemainsPartial(t *testing.T) {
	job := networkContextJob(t)
	before := proto.Clone(job)
	c, err := NewContextV2(job)
	if err != nil || c.networkMode != "allowlist" || !proto.Equal(before, job) {
		t.Fatal("network context", err)
	}
	proof, err := Build(c, "runner-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFrozenV2(proof, job, "runner-1"); err != nil {
		t.Fatal("frozen versioned proof", err)
	}
	if err := ValidateFrozen(proof, job, "runner-1"); err == nil {
		t.Fatal("v1 frozen reader admitted v2 bytes")
	}
	var value map[string]any
	if json.Unmarshal(proof.CanonicalJson, &value) != nil || value["runtime"] != nil || value["completeness"] != "partial" {
		t.Fatal("unmeasured enabled network became a runtime claim")
	}
	measured := measuredFixture() // exact existing synthetic none-only measurement
	if _, err := Build(c, "runner-1", nil, &measured); err != ErrInvalid {
		t.Fatal("none measurement described an enabled grant", err)
	}
	if _, err := NewContext(job); err != ErrInvalid {
		t.Fatal("v1 evidence admitted configuration v2", err)
	}
	// Mutable caller inputs cannot rewrite an already constructed context.
	job.EffectivePolicy.NetworkV2.Permissions[0].Hostname = "changed.example"
	replay, err := Build(c, "runner-1", nil)
	if err != nil || !bytes.Equal(proof.CanonicalJson, replay.CanonicalJson) {
		t.Fatal("caller rewrote frozen context", err)
	}
}

func TestNetworkV2TerminalContextRefusesImplicitOrWiderPolicy(t *testing.T) {
	for _, name := range []string{"mixed", "missing", "wider-cap", "tuple-cross-product", "legacy-json", "old-config", "unknown-config", "missing-v1-field", "duplicate-tuple"} {
		t.Run(name, func(t *testing.T) {
			job := networkContextJob(t)
			switch name {
			case "mixed":
				job.EffectivePolicy.Network = &runnerv1.NetworkPolicy{Mode: runnerv1.NetworkMode_NETWORK_MODE_NONE}
			case "missing":
				job.EffectivePolicy.NetworkV2 = nil
			case "wider-cap":
				job.EffectivePolicy.NetworkV2.MaximumConnections = 9
				setNetworkContextPolicyHash(t, job)
			case "tuple-cross-product":
				job.EffectivePolicy.NetworkV2.Permissions[0].Transport = runnerv1.NetworkTransportV2_NETWORK_TRANSPORT_V2_UDP
				setNetworkContextPolicyHash(t, job)
			case "legacy-json":
				raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(job.EffectivePolicy)
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(raw)
				job.Hashes.Policy.Value = hash[:]
			case "old-config":
				old := productionJob(t)
				job.NormalizedConfigurationJson, job.Hashes.Configuration = old.NormalizedConfigurationJson, old.Hashes.Configuration
			default:
				var document map[string]any
				if json.Unmarshal(job.NormalizedConfigurationJson, &document) != nil {
					t.Fatal("fixture")
				}
				if name == "unknown-config" {
					document["unauthorizedOverride"] = true
				}
				if name == "missing-v1-field" {
					delete(document, "project")
				}
				if name == "duplicate-tuple" {
					network := document["network"].(map[string]any)
					tuples := network["permissions"].([]any)
					network["permissions"] = append(tuples, tuples[0])
				}
				raw, err := canonicalJSON(document)
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(raw)
				job.NormalizedConfigurationJson, job.Hashes.Configuration.Value = raw, hash[:]
			}
			if _, err := NewContextV2(job); err == nil {
				t.Fatal("invalid network context admitted")
			}
		})
	}
}
