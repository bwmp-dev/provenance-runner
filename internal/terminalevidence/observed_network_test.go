package terminalevidence

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
)

func TestNetworkEvidenceRequiresSealedObservation(t *testing.T) {
	job := networkContextJob(t)
	c, err := NewContextV2(job)
	if err != nil {
		t.Fatal(err)
	}
	for _, observation := range []*runtimeidentity.NetworkObservation{nil, {}} {
		if proof, err := BuildObservedNetwork(c, "runner-1", nil, observation); err == nil || proof != nil {
			t.Fatal("unobserved runtime accepted")
		}
	}
	var decoded runtimeidentity.NetworkObservation
	if json.Unmarshal([]byte(`{"observed":true,"snapshot":{"networkMode":"allowlist"}}`), &decoded) != nil {
		t.Fatal("fixture")
	}
	if proof, err := BuildObservedNetwork(c, "runner-1", nil, &decoded); err == nil || proof != nil {
		t.Fatal("JSON minted runtime observation")
	}
	snapshot := measuredFixture()
	snapshot.NetworkMode = "allowlist"
	if proof, err := Build(c, "runner-1", nil, &snapshot); err == nil || proof != nil {
		t.Fatal("unsealed network label accepted")
	}
}

func TestFrozenNetworkRepresentationIsStrictAndNotANewMeasurement(t *testing.T) {
	job := networkContextJob(t)
	c, err := NewContextV2(job)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := measuredFixture()
	snapshot.NetworkMode = "allowlist"
	// Private reconstruction exercises the historical validator only. Public
	// Build still rejects this same unsealed snapshot in the test above.
	proof, err := build(c, "runner-1", nil, nil, true, &snapshot)
	if err != nil || ValidateFrozenV2(proof, job, "runner-1") != nil {
		t.Fatal("historical representation", err)
	}
	validateV2Reference(t, c, proof)
	if ValidateFrozen(proof, job, "runner-1") == nil {
		t.Fatal("network evidence admitted by v1 reader")
	}
	for _, mutate := range []func(map[string]any){
		func(r map[string]any) { r["networkMode"] = "restricted" },
		func(r map[string]any) { r["networkMode"] = "host" },
		func(r map[string]any) { r["sandboxExecutableSha256"] = "requested" },
		func(r map[string]any) { r["unexpected"] = "field" },
	} {
		var document map[string]any
		if json.Unmarshal(proof.CanonicalJson, &document) != nil {
			t.Fatal("fixture")
		}
		mutate(document["runtime"].(map[string]any))
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		original, originalDigest := proof.CanonicalJson, proof.Digest.Value
		hash := sha256.Sum256(raw)
		proof.CanonicalJson, proof.Digest.Value = raw, hash[:]
		if ValidateFrozenV2(proof, job, "runner-1") == nil {
			t.Fatal("invalid historical runtime accepted")
		}
		proof.CanonicalJson, proof.Digest.Value = original, originalDigest
	}
}
