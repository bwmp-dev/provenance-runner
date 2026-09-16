//go:build linux

package measuredservice

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func realPaperInput(t *testing.T, name, expected string, maximum int64) []byte {
	t.Helper()
	f, err := os.Open("/paper-fixture/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	digest := sha256.Sum256(raw)
	if err != nil || int64(len(raw)) > maximum || hex.EncodeToString(digest[:]) != expected {
		t.Fatal("real Paper input identity", name)
	}
	return raw
}

func realPaperFixtureJob(t *testing.T, java, prepared, server, target []byte) (*paper.RuntimeSource, paper.SignedRuntime, *p.JobSpecification) {
	t.Helper()
	source, manifest, job := serviceFixtureJob(t, java, prepared)
	var payload struct {
		RuntimeID string        `json:"runtimeId"`
		Catalog   paper.Catalog `json:"catalog"`
	}
	if json.Unmarshal(manifest.Payload, &payload) != nil {
		t.Fatal("fixture manifest")
	}
	alpha := paper.AlphaCatalog()
	payload.Catalog.Java.ArchiveRoot = alpha.Java.ArchiveRoot
	payload.Catalog.Java.MaximumExpandedBytes = alpha.Java.MaximumExpandedBytes
	payload.Catalog.PreparedRuntime.MaximumExpandedBytes = 256 << 20
	payload.Catalog.Paper.Artifact = alpha.Paper.Artifact
	identity := sha256.Sum256([]byte(fmt.Sprintf("provenance.paper-runtime/v1\n%s\x00%d\x00%s\x00%s\x00%s\x00linux\x00amd64", alpha.Paper.GameVersion, alpha.Paper.Build, alpha.Paper.Artifact.SHA256, alpha.Java.Distribution, alpha.Java.Version)))
	payload.RuntimeID = hex.EncodeToString(identity[:])
	payload.Catalog.EnvironmentID = "paper-runtime-" + payload.RuntimeID
	for _, pin := range []*paper.ArtifactPin{&payload.Catalog.Java.Artifact, &payload.Catalog.Paper.Artifact, &payload.Catalog.Probe, &payload.Catalog.PreparedRuntime.Artifact} {
		pin.URI = source.Origin + "/v1/paper-runtime-assets/" + pin.SHA256 + "/" + pin.Filename
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{57}, 32))
	manifest = paper.SignedRuntime{Payload: raw, Signature: ed25519.Sign(key, append([]byte("provenance.paper-runtime/v1\n"), raw...))}
	job.TargetPluginName = "ProvenanceSuccess"
	job.Lease.ExpiresAt = timestamppb.New(time.Now().Add(10 * time.Minute))
	job.Environment.ServerBinary = fixtureDigest(server)
	job.Artifact.Digest, job.Artifact.SizeBytes = fixtureDigest(target), int64(len(target))
	job.Hashes.Artifact = fixtureDigest(target)
	job.EffectivePolicy.Resources = &p.ResourceLimits{CpuMillis: 2000, MemoryBytes: 2 << 30, DiskBytes: 2 << 30, ProcessCount: 256}
	job.EffectivePolicy.PreparationTimeout = durationpb.New(90 * time.Second)
	job.EffectivePolicy.ExecutionTimeout = durationpb.New(180 * time.Second)
	job.EffectivePolicy.GracefulShutdownTimeout = durationpb.New(10 * time.Second)
	var config map[string]any
	if json.Unmarshal(job.NormalizedConfigurationJson, &config) != nil {
		t.Fatal("fixture configuration")
	}
	config["project"].(map[string]any)["name"] = job.TargetPluginName
	config["resources"] = map[string]any{"cpuCores": 2, "memoryMiB": 2048, "diskMiB": 2048, "processes": 256, "wallTimeoutSeconds": 180, "logBytes": 1 << 20}
	// Query the loaded plugin's local metadata. Bare "version" starts Paper's
	// asynchronous internet update check, which this offline fixture denies.
	config["tests"] = map[string]any{"startup": map[string]any{"timeoutSeconds": 120, "stabilizationSeconds": 1, "requirePluginEnabled": true, "shutdownTimeoutSeconds": 10, "requireCleanShutdown": true}, "console": []any{map[string]any{"id": "plugin-version", "command": "version ProvenanceSuccess", "timeoutSeconds": 10, "assertions": []any{map[string]any{"stream": "combined", "operator": "contains", "pattern": "ProvenanceSuccess version 1.0.0", "match": "present", "minimumOccurrences": 1}}}}}
	job.NormalizedConfigurationJson, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Configuration = fixtureDigest(job.NormalizedConfigurationJson)
	policy, err := np.EffectivePolicyV2SHA256(job.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Policy = &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: policy[:]}
	environment, err := proto.MarshalOptions{Deterministic: true}.Marshal(job.Environment)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes.Environment = fixtureDigest(environment)
	return source, manifest, job
}

func TestMeasuredPaperRealKernel(t *testing.T) {
	if os.Getenv("PROVENANCE_DISPOSABLE_REAL_PAPER_FIXTURE") != "1" {
		t.Skip("explicit real Paper fixture required")
	}
	measuredPaperServiceKernel(t, "real")
}

func TestRealPaperFixtureContract(t *testing.T) {
	_, _, job := realPaperFixtureJob(t, []byte("java"), []byte("prepared"), []byte("paper"), []byte("target"))
	if _, err := terminalevidence.NewContextV2(job); err != nil {
		t.Fatal("real fixture contract", err)
	}
}
