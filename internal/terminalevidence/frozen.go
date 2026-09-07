package terminalevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

// ValidateFrozen accepts only this producer's exact frozen representation,
// bound to the immutable executed specification. Empty runnerID is restricted
// to journal loading before authentication; delivery supplies the real runner.
func ValidateFrozen(proof *runnerv1.ExecutionEvidence, job *runnerv1.JobSpecification, runnerID string) error {
	if proof == nil {
		return nil
	}
	if len(proof.GetCanonicalJson()) == 0 || len(proof.GetCanonicalJson()) > MaximumBytes || len(proof.ProtoReflect().GetUnknown()) != 0 || proof.GetDigest() == nil || len(proof.GetDigest().ProtoReflect().GetUnknown()) != 0 {
		return ErrInvalid
	}
	h := sha256.Sum256(proof.GetCanonicalJson())
	if digest(proof.GetDigest()) == "" || !bytes.Equal(h[:], proof.GetDigest().GetValue()) {
		return ErrInvalid
	}
	value, err := parseJSON(proof.GetCanonicalJson())
	if err != nil {
		return ErrInvalid
	}
	document, ok := value.(map[string]any)
	if !ok {
		return ErrInvalid
	}
	encoded, err := json.Marshal(document["binding"])
	if err != nil {
		return ErrInvalid
	}
	var binding Binding
	if json.Unmarshal(encoded, &binding) != nil {
		return ErrInvalid
	}
	if runnerID != "" && binding.RunnerID != runnerID {
		return ErrInvalid
	}
	c, err := NewContext(job)
	if err != nil || !c.Matches(job.GetLease(), job.GetAttempt()) {
		return ErrInvalid
	}
	entries, ok := document["assertions"].([]any)
	if !ok || len(entries) > MaximumObservations {
		return ErrInvalid
	}
	observations := make([]Observation, 0, len(entries))
	for _, entry := range entries {
		a, ok := entry.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		id, ok := a["id"].(string)
		if !ok {
			return ErrInvalid
		}
		p, ok := c.planned[id]
		if !ok || !p.supported {
			return ErrInvalid
		}
		preimage, ok := a["evidence"].(map[string]any)
		if !ok {
			return ErrInvalid
		}
		v, ok := preimage["observation"].(map[string]any)
		if !ok {
			return ErrInvalid
		}
		flag := func(key string) bool { value, _ := v[key].(bool); return value }
		observations = append(observations, Observation{Type: p.kind, Name: p.name, TestID: p.selector["testId"], AssertionID: p.selector["assertionId"], ServerLoaded: flag("serverLoaded"), StabilizationCompleted: flag("stabilizationCompleted"), ServerReady: flag("serverReady"), RequirementsSatisfied: flag("requirementsSatisfied"), Loaded: flag("loaded"), Enabled: flag("enabled"), Registered: flag("registered"), ExecutionCompleted: flag("executionCompleted"), Evaluated: flag("evaluated"), Passed: flag("passed"), OutputTruncated: flag("outputTruncated"), ShutdownRequested: flag("shutdownRequested"), ServerStopped: flag("serverStopped"), ReportedShutdownRequested: flag("reportedShutdownRequested")})
	}
	var measured *runtimeidentity.Snapshot
	if document["runtime"] != nil {
		encoded, err := json.Marshal(document["runtime"])
		if err != nil {
			return ErrInvalid
		}
		measured = new(runtimeidentity.Snapshot)
		if json.Unmarshal(encoded, measured) != nil || !measured.Valid() {
			return ErrInvalid
		}
	}
	expected, err := Build(c, binding.RunnerID, observations, measured)
	if err != nil || !bytes.Equal(expected.GetCanonicalJson(), proof.GetCanonicalJson()) {
		return ErrInvalid
	}
	return nil
}
