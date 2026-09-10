// Package terminalevidence projects bounded IFC-019 evidence. It is not an
// issuer or a runtime measurement implementation.
package terminalevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

const MaximumBytes = 32 << 10
const MaximumObservations = 256

var ErrInvalid = errors.New("terminal evidence inputs are invalid")
var ErrBounds = errors.New("terminal evidence exceeds supported bounds")
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Observation contains only provider-validated closed facts. Names are local
// selectors, translated to immutable configuration IDs before serialization.
// No command, regex, output, exception, version or requested image is a fact.
type Observation struct {
	Type, Name, TestID, AssertionID                                          string
	ServerLoaded, StabilizationCompleted, ServerReady, RequirementsSatisfied bool
	Loaded, Enabled                                                          bool
	Registered, ExecutionCompleted, Evaluated, Passed, OutputTruncated       bool
	ShutdownRequested, ServerStopped, ReportedShutdownRequested              bool
}

type Binding struct {
	RunnerID      string `json:"runnerId"`
	JobID         string `json:"jobId"`
	ExecutionID   string `json:"executionId"`
	LeaseID       string `json:"leaseId"`
	AttemptID     string `json:"attemptId"`
	CandidateID   string `json:"candidateId"`
	MatrixEntryID string `json:"matrixEntryId"`
	AttemptNumber uint32 `json:"attemptNumber"`
}

type planned struct {
	id, kind, name string
	supported      bool
	selector       map[string]string
}

// Context has no exported mutable fields. It contains no URLs or credentials.
type Context struct {
	binding   Binding
	requested map[string]any
	planned   map[string]planned
	v2        bool
}

func (c *Context) Matches(lease *runnerv1.LeaseIdentity, attempt *runnerv1.AttemptIdentity) bool {
	return c != nil && c.binding.JobID == lease.GetJobId() && c.binding.ExecutionID == lease.GetExecutionId() && c.binding.LeaseID == lease.GetLeaseId() && c.binding.AttemptID == attempt.GetAttemptId() && c.binding.CandidateID == attempt.GetReleaseCandidateId() && c.binding.MatrixEntryID == attempt.GetMatrixEntryId() && c.binding.AttemptNumber == attempt.GetAttemptNumber()
}

// Build freezes exact canonical bytes once. Legacy directory trees remain
// null/partial; only an execution-bound measurement may populate runtime.
func Build(c *Context, runnerID string, observations []Observation, measured ...*runtimeidentity.Snapshot) (*runnerv1.ExecutionEvidence, error) {
	if c == nil || !identifier.MatchString(runnerID) {
		return nil, ErrInvalid
	}
	if len(observations) > MaximumObservations {
		return nil, ErrBounds
	}
	binding := c.binding
	binding.RunnerID = runnerID
	// All serialized keys and strings are closed ASCII identifiers, hex digests
	// or enums. encoding/json's sorted map keys therefore equal RFC8785's UTF16
	// ordering and escaping on this restricted producer domain.
	b, _ := json.Marshal(binding)
	var bound map[string]any
	_ = json.Unmarshal(b, &bound)
	assertions := make([]any, 0, len(observations))
	seen := map[string]bool{}
	for _, o := range observations {
		p, ok := c.find(o)
		if !ok {
			return nil, ErrInvalid
		}
		// Optional requirements and unsupported operators produce no claims.
		if !p.supported {
			continue
		}
		if seen[p.id] {
			return nil, ErrInvalid
		}
		seen[p.id] = true
		value, outcome, err := observationValue(o)
		if err != nil {
			return nil, err
		}
		for key, v := range p.selector {
			value[key] = v
		}
		preimage := map[string]any{"binding": bound, "id": p.id, "type": p.kind, "outcome": outcome, "observation": value}
		encoded, err := json.Marshal(preimage)
		if err != nil {
			return nil, ErrInvalid
		}
		hash := sha256.Sum256(encoded)
		assertions = append(assertions, map[string]any{"id": p.id, "type": p.kind, "outcome": outcome, "evidence": preimage, "evidenceSha256": hex.EncodeToString(hash[:])})
	}
	sort.Slice(assertions, func(i, j int) bool {
		return assertions[i].(map[string]any)["id"].(string) < assertions[j].(map[string]any)["id"].(string)
	})
	var runtime any
	completeness := "partial"
	if len(measured) > 1 {
		return nil, ErrInvalid
	}
	if len(measured) == 1 && measured[0] != nil {
		copy := *measured[0]
		if !copy.Valid() {
			return nil, ErrInvalid
		}
		encoded, _ := json.Marshal(copy)
		if json.Unmarshal(encoded, &runtime) != nil {
			return nil, ErrInvalid
		}
		complete := true
		for _, p := range c.planned {
			if !p.supported || !seen[p.id] {
				complete = false
			}
		}
		if complete {
			completeness = "complete"
		}
	}
	version := "provenance.execution-evidence/v1"
	if c.v2 {
		version = "provenance.execution-evidence/v2"
	}
	document := map[string]any{"schemaVersion": version, "binding": bound, "requested": c.requested, "runtime": runtime, "assertions": assertions, "completeness": completeness}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(encoded) > MaximumBytes {
		return nil, ErrBounds
	}
	hash := sha256.Sum256(encoded)
	return &runnerv1.ExecutionEvidence{CanonicalJson: encoded, Digest: &runnerv1.Digest{Algorithm: runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: hash[:]}}, nil
}

func (c *Context) find(o Observation) (planned, bool) {
	id := o.Type
	if o.Type == "console-regex" || o.Type == "console-contains" {
		id = o.Type + ":" + o.AssertionID
	}
	if o.Type == "dependency-present" {
		for _, p := range c.planned {
			if p.kind == o.Type && strings.EqualFold(p.name, o.Name) {
				return p, true
			}
		}
		return planned{}, false
	}
	p, ok := c.planned[id]
	if !ok {
		return planned{}, false
	}
	if p.kind != o.Type || (o.Type == "plugin-enabled" && !strings.EqualFold(o.Name, p.name)) || ((o.Type == "console-regex" || o.Type == "console-contains") && (o.TestID != p.selector["testId"] || o.AssertionID != p.selector["assertionId"])) {
		return planned{}, false
	}
	return p, true
}

func observationValue(o Observation) (map[string]any, string, error) {
	v := map[string]any{}
	passed := false
	switch o.Type {
	case "startup-ready":
		if !o.ServerLoaded || !o.StabilizationCompleted || !o.ServerReady {
			return nil, "", ErrInvalid
		}
		v = map[string]any{"serverLoaded": o.ServerLoaded, "stabilizationCompleted": o.StabilizationCompleted, "serverReady": o.ServerReady, "requirementsSatisfied": o.RequirementsSatisfied}
		passed = o.RequirementsSatisfied
	case "plugin-enabled", "dependency-present":
		if o.Enabled && !o.Loaded {
			return nil, "", ErrInvalid
		}
		v = map[string]any{"loaded": o.Loaded, "enabled": o.Enabled}
		passed = o.Loaded && o.Enabled
	case "console-regex", "console-contains":
		if !o.Registered || !o.ExecutionCompleted || (!o.Evaluated && (o.Passed || !o.OutputTruncated)) || (o.Passed && o.OutputTruncated) {
			return nil, "", ErrInvalid
		}
		v = map[string]any{"registered": o.Registered, "executionCompleted": o.ExecutionCompleted, "evaluated": o.Evaluated, "passed": o.Passed, "outputTruncated": o.OutputTruncated}
		passed = o.Passed
		if !o.Evaluated {
			return v, "skipped", nil
		}
	case "clean-shutdown":
		if !o.ShutdownRequested || !o.ServerStopped {
			return nil, "", ErrInvalid
		}
		v = map[string]any{"shutdownRequested": o.ShutdownRequested, "serverStopped": o.ServerStopped, "reportedShutdownRequested": o.ReportedShutdownRequested}
		passed = o.ReportedShutdownRequested
	default:
		return nil, "", ErrInvalid
	}
	outcome := "failed"
	if passed {
		outcome = "passed"
	}
	return v, outcome, nil
}
