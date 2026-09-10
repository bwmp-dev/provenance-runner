package terminalevidence

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/pluginname"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

//go:embed schema/config.json
var schemaBytes []byte
var schemaOnce sync.Once
var configurationSchema *jsonschema.Schema
var schemaError error

type noRemoteSchemas struct{}

func (noRemoteSchemas) Load(string) (any, error) { return nil, ErrInvalid }

type ecmaRegex struct {
	pattern    string
	expression *regexp2.Regexp
}

func (r ecmaRegex) String() string { return r.pattern }
func (r ecmaRegex) MatchString(value string) bool {
	matched, err := r.expression.MatchString(value)
	return err == nil && matched
}

func validatedConfiguration(raw []byte) (map[string]any, error) {
	v, err := parseJSON(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	canonical, err := canonicalJSON(v)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrInvalid
	}
	schemaOnce.Do(func() {
		var document any
		if json.Unmarshal(schemaBytes, &document) != nil {
			schemaError = ErrInvalid
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.AssertFormat()
		compiler.UseLoader(noRemoteSchemas{})
		compiler.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
			r, err := regexp2.Compile(pattern, regexp2.ECMAScript)
			if err != nil {
				return nil, err
			}
			r.MatchTimeout = 100 * time.Millisecond
			return ecmaRegex{pattern, r}, nil
		})
		const uri = "https://schemas.provenance.dev/config/v1/schema.json"
		if compiler.AddResource(uri, document) != nil {
			schemaError = ErrInvalid
			return
		}
		configurationSchema, schemaError = compiler.Compile(uri)
	})
	if schemaError != nil || configurationSchema.Validate(v) != nil {
		return nil, ErrInvalid
	}
	value, ok := v.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	return value, nil
}

// NewContext requires already normalized schema-valid configuration. It never
// supplies defaults, rewrites hashes or borrows mutable runner capabilities.
func NewContext(job *runnerv1.JobSpecification) (*Context, error) {
	return newContext(job, false)
}

// NewContextV2 binds literal operators to a distinct version. Callers must not
// use this until v2 is admitted; existing contexts and queued bytes remain v1.
func NewContextV2(job *runnerv1.JobSpecification) (*Context, error) {
	return newContext(job, true)
}

func newContext(job *runnerv1.JobSpecification, v2 bool) (*Context, error) {
	if job == nil || job.GetEnvironment().GetProvider() != runnerv1.ServerProvider_SERVER_PROVIDER_PAPER || job.GetEffectivePolicy() == nil {
		return nil, ErrInvalid
	}
	lease, attempt := job.GetLease(), job.GetAttempt()
	b := Binding{JobID: lease.GetJobId(), ExecutionID: lease.GetExecutionId(), LeaseID: lease.GetLeaseId(), AttemptID: attempt.GetAttemptId(), CandidateID: attempt.GetReleaseCandidateId(), MatrixEntryID: attempt.GetMatrixEntryId(), AttemptNumber: attempt.GetAttemptNumber()}
	for _, id := range []string{b.JobID, b.ExecutionID, b.LeaseID, b.AttemptID, b.CandidateID, b.MatrixEntryID} {
		if !identifier.MatchString(id) {
			return nil, ErrInvalid
		}
	}
	if b.AttemptNumber == 0 {
		return nil, ErrInvalid
	}
	if _, err := validatedConfiguration(job.GetNormalizedConfigurationJson()); err != nil {
		return nil, err
	}
	var config struct {
		Dependencies []struct {
			ID       string `json:"id"`
			SHA256   string `json:"sha256"`
			Required bool   `json:"required"`
		} `json:"dependencies"`
		Tests struct {
			Startup struct {
				Plugin   bool `json:"requirePluginEnabled"`
				Shutdown bool `json:"requireCleanShutdown"`
			} `json:"startup"`
			Console []struct {
				ID         string `json:"id"`
				Assertions []struct {
					Operator *string `json:"operator"`
				} `json:"assertions"`
			} `json:"console"`
		} `json:"tests"`
	}
	if json.Unmarshal(job.GetNormalizedConfigurationJson(), &config) != nil {
		return nil, ErrInvalid
	}
	h := job.GetHashes()
	artifact, configuration, environment, policy := digest(h.GetArtifact()), digest(h.GetConfiguration()), digest(h.GetEnvironment()), digest(h.GetPolicy())
	actual := sha256.Sum256(job.GetNormalizedConfigurationJson())
	if artifact == "" || configuration != hex.EncodeToString(actual[:]) || environment == "" || policy == "" || artifact != digest(job.GetArtifact().GetDigest()) || job.GetArtifact().GetSizeBytes() == 0 || !policyMatches(job.GetEffectivePolicy(), policy) || !pluginname.ValidPaper(job.GetTargetPluginName()) {
		return nil, ErrInvalid
	}
	c := &Context{binding: b, requested: map[string]any{"artifactSha256": artifact, "configurationSha256": configuration, "environmentSha256": environment, "policySha256": policy}, planned: map[string]planned{}}
	c.v2 = v2
	add := func(id, kind, name string, supported bool, selector map[string]string) error {
		if !identifier.MatchString(id) {
			return ErrInvalid
		}
		if _, exists := c.planned[id]; exists {
			return ErrInvalid
		}
		c.planned[id] = planned{id, kind, name, supported, selector}
		return nil
	}
	add("startup-ready", "startup-ready", "", true, nil)
	add("plugin-enabled", "plugin-enabled", job.GetTargetPluginName(), config.Tests.Startup.Plugin, map[string]string{"targetId": "target"})
	add("clean-shutdown", "clean-shutdown", "", config.Tests.Startup.Shutdown, nil)
	if len(config.Dependencies) != len(job.GetDependencies()) || len(config.Dependencies) != len(h.GetDependencies()) {
		return nil, ErrInvalid
	}
	inputs := map[string]*runnerv1.DependencyInput{}
	hashes := map[string]*runnerv1.DependencyDigest{}
	names := map[string]bool{strings.ToLower(job.GetTargetPluginName()): true}
	for _, d := range job.GetDependencies() {
		if d == nil || inputs[d.GetDependencyId()] != nil || !pluginname.ValidPaper(d.GetPluginName()) || names[strings.ToLower(d.GetPluginName())] {
			return nil, ErrInvalid
		}
		inputs[d.GetDependencyId()] = d
		names[strings.ToLower(d.GetPluginName())] = true
	}
	for _, d := range h.GetDependencies() {
		if d == nil || hashes[d.GetDependencyId()] != nil {
			return nil, ErrInvalid
		}
		hashes[d.GetDependencyId()] = d
	}
	dependencies := []any{}
	seen := map[string]bool{}
	for _, d := range config.Dependencies {
		input, hash := inputs[d.ID], hashes[d.ID]
		if seen[d.ID] || input == nil || hash == nil || d.SHA256 != digest(input.GetObject().GetDigest()) || d.SHA256 != digest(hash.GetDigest()) || input.GetObject().GetSizeBytes() == 0 || input.GetObject().GetFilename() != hash.GetFilename() {
			return nil, ErrInvalid
		}
		seen[d.ID] = true
		dependencies = append(dependencies, map[string]any{"id": d.ID, "sha256": d.SHA256})
		if err := add("dependency-present:"+d.ID, "dependency-present", input.GetPluginName(), d.Required, map[string]string{"dependencyId": d.ID, "dependencySha256": d.SHA256}); err != nil {
			return nil, err
		}
	}
	sort.Slice(dependencies, func(i, j int) bool {
		return dependencies[i].(map[string]any)["id"].(string) < dependencies[j].(map[string]any)["id"].(string)
	})
	c.requested["dependencies"] = dependencies
	for _, test := range config.Tests.Console {
		for n, a := range test.Assertions {
			selector := fmt.Sprintf("%s:%d", test.ID, n+1)
			kind, supported := "console-regex", a.Operator != nil && *a.Operator == "regex"
			if v2 && a.Operator != nil && *a.Operator == "contains" {
				kind, supported = "console-contains", true
			}
			if err := add(kind+":"+selector, kind, "", supported, map[string]string{"testId": test.ID, "assertionId": selector}); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

func digest(d *runnerv1.Digest) string {
	if d == nil || d.GetAlgorithm() != runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 || len(d.GetValue()) != sha256.Size {
		return ""
	}
	return hex.EncodeToString(d.GetValue())
}
func policyMatches(policy *runnerv1.EffectivePolicy, want string) bool {
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(policy)
	if err != nil {
		return false
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) == want {
		return true
	}
	raw, err = (protojson.MarshalOptions{UseProtoNames: true}).Marshal(policy)
	if err != nil {
		return false
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return false
	}
	spaced := []byte{}
	inString, escaped := false, false
	for _, b := range compact.Bytes() {
		spaced = append(spaced, b)
		if inString {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				inString = false
			}
			continue
		}
		if b == '"' {
			inString = true
		} else if b == ',' {
			spaced = append(spaced, ' ')
		}
	}
	for _, bytes := range [][]byte{compact.Bytes(), spaced} {
		h := sha256.Sum256(bytes)
		if hex.EncodeToString(h[:]) == want {
			return true
		}
	}
	return false
}
