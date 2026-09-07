package terminalevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
)

func TestClosedObservationPredicatesExhaustive(t *testing.T) {
	for bits := 0; bits < 32; bits++ {
		b := func(i int) bool { return bits&(1<<i) != 0 }
		cases := []struct {
			o                 Observation
			valid, pass, skip bool
		}{
			{Observation{Type: "startup-ready", ServerLoaded: b(0), StabilizationCompleted: b(1), ServerReady: b(2), RequirementsSatisfied: b(3)}, b(0) && b(1) && b(2), b(3), false},
			{Observation{Type: "plugin-enabled", Loaded: b(0), Enabled: b(1)}, !b(1) || b(0), b(0) && b(1), false},
			{Observation{Type: "dependency-present", Loaded: b(0), Enabled: b(1)}, !b(1) || b(0), b(0) && b(1), false},
			{Observation{Type: "clean-shutdown", ShutdownRequested: b(0), ServerStopped: b(1), ReportedShutdownRequested: b(2)}, b(0) && b(1), b(2), false},
			{Observation{Type: "console-regex", Registered: b(0), ExecutionCompleted: b(1), Evaluated: b(2), Passed: b(3), OutputTruncated: b(4)}, b(0) && b(1) && (b(2) || (!b(3) && b(4))) && !(b(3) && b(4)), b(3), !b(2)},
		}
		for _, tc := range cases {
			_, outcome, err := observationValue(tc.o)
			if (err == nil) != tc.valid {
				t.Fatalf("%s bits%d validity", tc.o.Type, bits)
			}
			if err == nil {
				want := "failed"
				if tc.pass {
					want = "passed"
				}
				if tc.skip {
					want = "skipped"
				}
				if outcome != want {
					t.Fatalf("%s bits%d outcome %s", tc.o.Type, bits, outcome)
				}
			}
		}
	}
}

func TestProofByteBoundDoesNotSilentlyTrimObservations(t *testing.T) {
	c, err := NewContext(productionJob(t))
	if err != nil {
		t.Fatal(err)
	}
	observations := make([]Observation, 256)
	for i := range observations {
		id := fmt.Sprintf("test-%03d", i)
		selector := id + ":1"
		c.planned["console-regex:"+selector] = planned{id: "console-regex:" + selector, kind: "console-regex", supported: true, selector: map[string]string{"testId": id, "assertionId": selector}}
		observations[i] = Observation{Type: "console-regex", TestID: id, AssertionID: selector, Registered: true, ExecutionCompleted: true, Evaluated: true, Passed: true}
	}
	if proof, err := Build(c, "runner-1", observations); err != ErrBounds || proof != nil {
		t.Fatal("oversized proof silently emitted/truncated")
	}
	small, err := Build(c, "runner-1", observations[:1])
	if err != nil || small == nil {
		t.Fatal("bounded proof rejected")
	}
	if _, err := Build(c, "runner-1", append(observations[:1:1], observations[0])); err == nil {
		t.Fatal("duplicate observed assertion accepted")
	}
}

func TestConfigurationRejectsMalformedNoncanonicalAndSchemaInvalid(t *testing.T) {
	original := productionJob(t)
	for name, raw := range map[string][]byte{
		"bom":        append([]byte{0xef, 0xbb, 0xbf}, original.NormalizedConfigurationJson...),
		"trailing":   append(append([]byte{}, original.NormalizedConfigurationJson...), []byte("{}")...),
		"whitespace": append([]byte(" "), original.NormalizedConfigurationJson...),
		"duplicate":  []byte(`{"apiVersion":"provenance.dev/v1","apiVersion":"provenance.dev/v1"}`),
		"surrogate":  []byte(`{"a":"\ud800"}`),
		"utf8":       {'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'},
		"unknown":    []byte(`{"unknown":true}`),
		"unsafe":     []byte(`{"a":9007199254740993}`),
	} {
		t.Run(name, func(t *testing.T) {
			job := productionJob(t)
			job.NormalizedConfigurationJson = raw
			h := sha256.Sum256(raw)
			job.Hashes.Configuration.Value = h[:]
			if _, err := NewContext(job); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestOptionalAndUnsupportedDoNotBecomeAssertions(t *testing.T) {
	job := productionJob(t)
	var configuration map[string]any
	json.Unmarshal(job.NormalizedConfigurationJson, &configuration)
	startup := configuration["tests"].(map[string]any)["startup"].(map[string]any)
	startup["requirePluginEnabled"] = false
	startup["requireCleanShutdown"] = false
	raw, err := canonicalJSON(configuration)
	if err != nil {
		t.Fatal(err)
	}
	job.NormalizedConfigurationJson = raw
	h := sha256.Sum256(raw)
	job.Hashes.Configuration.Value = h[:]
	c, err := NewContext(job)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := Build(c, "runner-1", []Observation{{Type: "plugin-enabled", Name: job.TargetPluginName, Loaded: true, Enabled: true}, {Type: "clean-shutdown", ShutdownRequested: true, ServerStopped: true, ReportedShutdownRequested: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(proof.CanonicalJson, []byte(`"assertions":[]`)) {
		t.Fatal("optional observations became claims")
	}
	// Unknown absence remains an empty partial proof; it is never synthesized as failed/skipped.
	empty, err := Build(c, "runner-1", nil)
	if err != nil || !bytes.Equal(proof.CanonicalJson, empty.CanonicalJson) {
		t.Fatal("missing evidence was synthesized")
	}
}

func TestSchemaValidFractionalCPUAndExplicitConsoleOperator(t *testing.T) {
	for _, operator := range []string{"regex", "contains", ""} {
		job := productionJob(t)
		var configuration map[string]any
		json.Unmarshal(job.NormalizedConfigurationJson, &configuration)
		configuration["resources"].(map[string]any)["cpuCores"] = 0.1
		assertion := map[string]any{"stream": "combined", "pattern": "safe", "match": "present"}
		if operator != "" {
			assertion["operator"] = operator
		}
		configuration["tests"].(map[string]any)["console"] = []any{map[string]any{"id": "check", "command": "version", "timeoutSeconds": float64(10), "assertions": []any{assertion}}}
		raw, err := canonicalJSON(configuration)
		if err != nil {
			t.Fatal(err)
		}
		job.NormalizedConfigurationJson = raw
		hash := sha256.Sum256(raw)
		job.Hashes.Configuration.Value = hash[:]
		c, err := NewContext(job)
		if err != nil {
			t.Fatalf("valid fractional configuration rejected: %v", err)
		}
		proof, err := Build(c, "runner-1", []Observation{{Type: "console-regex", TestID: "check", AssertionID: "check:1", Registered: true, ExecutionCompleted: true, Evaluated: true, Passed: true}})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(proof.CanonicalJson, []byte(`"id":"console-regex:check:1"`)) != (operator == "regex") {
			t.Fatal("absent/contains operator promoted or regex lost")
		}
	}
}
