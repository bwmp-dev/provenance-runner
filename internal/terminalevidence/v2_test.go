package terminalevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"testing"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

func TestV2LiteralVersionBoundContext(t *testing.T) {
	for _, operator := range []string{"contains", "regex", ""} {
		for _, match := range []string{"present", "absent"} {
			t.Run(operator+"/"+match, func(t *testing.T) {
				job := productionJob(t)
				var config map[string]any
				if json.Unmarshal(job.NormalizedConfigurationJson, &config) != nil {
					t.Fatal("config")
				}
				a := map[string]any{"stream": "combined", "pattern": "literal.+", "match": match}
				if operator != "" {
					a["operator"] = operator
				}
				config["tests"].(map[string]any)["console"] = []any{map[string]any{"id": "check", "command": "version", "timeoutSeconds": float64(10), "assertions": []any{a}}}
				raw, err := canonicalJSON(config)
				if err != nil {
					t.Fatal(err)
				}
				job.NormalizedConfigurationJson = raw
				h := sha256.Sum256(raw)
				job.Hashes.Configuration.Value = h[:]
				v1, err := NewContext(job)
				if err != nil {
					t.Fatal(err)
				}
				v2, err := NewContextV2(job)
				if err != nil {
					t.Fatal(err)
				}
				kind := "console-regex"
				if operator == "contains" {
					kind = "console-contains"
				}
				o := Observation{Type: kind, TestID: "check", AssertionID: "check:1", Registered: true, ExecutionCompleted: true, Evaluated: true, Passed: true}
				proof, err := Build(v2, "runner-1", []Observation{o})
				if err != nil {
					t.Fatal(err)
				}
				var value map[string]any
				if json.Unmarshal(proof.CanonicalJson, &value) != nil || value["schemaVersion"] != "provenance.execution-evidence/v2" || value["completeness"] != "partial" {
					t.Fatal("version or missing runtime changed")
				}
				claims := value["assertions"].([]any)
				if (len(claims) == 1) != (operator != "") {
					t.Fatal("unsupported/default claim promoted")
				}
				if operator != "" && claims[0].(map[string]any)["type"] != kind {
					t.Fatal("operator changed")
				}
				if bytes.Contains(proof.CanonicalJson, []byte("literal.+")) {
					t.Fatal("pattern retained")
				}
				validateV2Reference(t, v2, proof)
				if err := ValidateFrozenV2(proof, job, "runner-1"); err != nil {
					t.Fatal("v2 frozen validation", err)
				}
				if err := ValidateFrozen(proof, job, "runner-1"); err != ErrInvalid {
					t.Fatal("v1 frozen validator admitted v2")
				}
				if err := ValidateFrozenV2(proof, job, "other-runner"); err != ErrInvalid {
					t.Fatal("runner substitution accepted")
				}
				if operator == "contains" {
					if _, err := Build(v1, "runner-1", []Observation{o}); err != ErrInvalid {
						t.Fatal("v1 admitted literal observation")
					}
					o.Type = "console-regex"
					if _, err := Build(v2, "runner-1", []Observation{o}); err != ErrInvalid {
						t.Fatal("literal retyped as regex")
					}
				}
				old, err := Build(v1, "runner-1", nil)
				if err != nil || !bytes.Contains(old.CanonicalJson, []byte(`"schemaVersion":"provenance.execution-evidence/v1"`)) {
					t.Fatal("v1 context changed")
				}
				if err := ValidateFrozenV2(old, job, "runner-1"); err != ErrInvalid {
					t.Fatal("v2 frozen validator admitted v1")
				}
			})
		}
	}
}

func validateV2Reference(t *testing.T, c *Context, proof *runnerv1.ExecutionEvidence) {
	t.Helper()
	// Accepted source e7b5404; no claim of a newly published toolkit release.
	reference, err := os.ReadFile("testdata/v2/reference.mjs")
	h := sha256.Sum256(reference)
	if err != nil || hex.EncodeToString(h[:]) != "955f25a3f36261caf82b6e6cf0e5ab141caa6f540d2616ee6ab2df925d80aea0" {
		t.Fatal("v2 source identity")
	}
	schema, err := os.ReadFile("testdata/v2/schema.json")
	sh := sha256.Sum256(schema)
	if err != nil || hex.EncodeToString(sh[:]) != "b8e4d533447750bf90e2100c4c7862951d30e2762797e342588ef43ee8503702" {
		t.Fatal("v2 schema identity")
	}
	var value map[string]any
	if json.Unmarshal(proof.CanonicalJson, &value) != nil {
		t.Fatal("proof")
	}
	assertions := []any{}
	for _, p := range c.planned {
		selector := p.selector
		if selector == nil {
			selector = map[string]string{}
		}
		assertions = append(assertions, map[string]any{"id": p.id, "type": p.kind, "supported": p.supported, "selector": selector})
	}
	sort.Slice(assertions, func(i, j int) bool {
		return assertions[i].(map[string]any)["id"].(string) < assertions[j].(map[string]any)["id"].(string)
	})
	input, _ := json.Marshal(map[string]any{"raw": string(proof.CanonicalJson), "digest": hex.EncodeToString(proof.Digest.Value), "expected": map[string]any{"featureV2Enabled": true, "wholeMessageBytes": len(proof.CanonicalJson) + 100, "binding": value["binding"], "requested": c.requested, "assertions": assertions}})
	command := exec.Command("node", "--input-type=module", "-e", `import {validateTerminal} from './testdata/v2/reference.mjs';let s='';for await(const c of process.stdin)s+=c;const x=JSON.parse(s);validateTerminal(Buffer.from(x.raw),x.digest,x.expected);`)
	command.Stdin = bytes.NewReader(input)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("reference rejected producer: %v %s", err, output)
	}
}
