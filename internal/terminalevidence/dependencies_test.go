package terminalevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func dependencyJob(t *testing.T) *runnerv1.JobSpecification {
	t.Helper()
	job := productionJob(t)
	var configuration map[string]any
	json.Unmarshal(job.NormalizedConfigurationJson, &configuration)
	hash := sha256.Sum256([]byte("synthetic dependency bytes"))
	digest := &runnerv1.Digest{Algorithm: runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: hash[:]}
	configuration["dependencies"] = []any{map[string]any{"id": "dep", "provider": "modrinth", "projectId": "project", "versionId": "version", "sha256": hex.EncodeToString(hash[:]), "required": true}}
	raw, err := canonicalJSON(configuration)
	if err != nil {
		t.Fatal(err)
	}
	job.NormalizedConfigurationJson = raw
	configHash := sha256.Sum256(raw)
	job.Hashes.Configuration.Value = configHash[:]
	job.Dependencies = []*runnerv1.DependencyInput{{DependencyId: "dep", PluginName: "DependencyPlugin", Object: &runnerv1.ObjectDownload{Digest: proto.Clone(digest).(*runnerv1.Digest), Filename: "dep.jar", SizeBytes: 26}}}
	job.Hashes.Dependencies = []*runnerv1.DependencyDigest{{DependencyId: "dep", Filename: "dep.jar", Digest: proto.Clone(digest).(*runnerv1.Digest)}}
	return job
}

func TestDependencyIdentityAndRequiredProjection(t *testing.T) {
	job := dependencyJob(t)
	c, err := NewContext(job)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := Build(c, "runner-1", []Observation{{Type: "dependency-present", Name: "dependencyplugin", Loaded: false, Enabled: false}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(proof.CanonicalJson, []byte(`"id":"dependency-present:dep"`)) || !bytes.Contains(proof.CanonicalJson, []byte(`"outcome":"failed"`)) {
		t.Fatal("known dependency absence lost")
	}
	if err := ValidateFrozen(proof, job, "runner-1"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*runnerv1.JobSpecification){
		"missing":          func(j *runnerv1.JobSpecification) { j.Dependencies = nil },
		"duplicate":        func(j *runnerv1.JobSpecification) { j.Dependencies = append(j.Dependencies, j.Dependencies[0]) },
		"id":               func(j *runnerv1.JobSpecification) { j.Dependencies[0].DependencyId = "other" },
		"input hash":       func(j *runnerv1.JobSpecification) { j.Dependencies[0].Object.Digest.Value[0] ^= 1 },
		"hash identity":    func(j *runnerv1.JobSpecification) { j.Hashes.Dependencies[0].Digest.Value[0] ^= 1 },
		"size":             func(j *runnerv1.JobSpecification) { j.Dependencies[0].Object.SizeBytes = 0 },
		"filename":         func(j *runnerv1.JobSpecification) { j.Hashes.Dependencies[0].Filename = "other.jar" },
		"plugin collision": func(j *runnerv1.JobSpecification) { j.Dependencies[0].PluginName = j.TargetPluginName },
		"policy":           func(j *runnerv1.JobSpecification) { j.Hashes.Policy.Value[0] ^= 1 },
		"artifact":         func(j *runnerv1.JobSpecification) { j.Artifact.Digest.Value[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			copy := proto.Clone(job).(*runnerv1.JobSpecification)
			mutate(copy)
			if _, err := NewContext(copy); err == nil {
				t.Fatal("identity substitution accepted")
			}
		})
	}
}
