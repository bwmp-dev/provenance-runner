package testsecrets

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"unicode/utf8"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

var selectionName = regexp.MustCompile(`^[a-z][a-z0-9]*([._-][a-z0-9]+)*$`)
var selectionUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidateSelection binds immutable metadata to normalized configuration. It
// never opens values. Duplicate JSON keys and non-integer versions are refused.
func ValidateSelection(job *runnerv1.JobSpecification) error {
	if job == nil || len(job.NormalizedConfigurationJson) == 0 || len(job.NormalizedConfigurationJson) > 65536 || len(job.TestSecrets) > 64 {
		return ErrUnavailable
	}
	if raw := bytes.TrimSpace(job.NormalizedConfigurationJson); len(raw) == 0 || raw[0] != '{' || !utf8.Valid(raw) {
		return ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(job.NormalizedConfigurationJson))
	decoder.UseNumber()
	if !uniqueJSONValue(decoder, 0) {
		return ErrUnavailable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrUnavailable
	}
	var configuration map[string]json.RawMessage
	if json.Unmarshal(job.NormalizedConfigurationJson, &configuration) != nil {
		return ErrUnavailable
	}
	var tests map[string]json.RawMessage
	if raw, exists := configuration["tests"]; exists {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &tests) != nil {
			return ErrUnavailable
		}
	}
	var selection map[string]uint64
	if raw, exists := tests["secrets"]; exists {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &selection) != nil {
			return ErrUnavailable
		}
	}
	if len(selection) != len(job.TestSecrets) {
		return ErrUnavailable
	}
	seen := make(map[string]bool, len(job.TestSecrets))
	previous := ""
	for _, ref := range job.TestSecrets {
		if ref == nil || len(ref.ProtoReflect().GetUnknown()) != 0 || !selectionName.MatchString(ref.Name) || len(ref.Name) > 63 || ref.Name <= previous || !selectionUUID.MatchString(ref.SecretId) || ref.SecretId == "00000000-0000-0000-0000-000000000000" || seen[ref.SecretId] || ref.Version == 0 || ref.Version > 9007199254740991 || selection[ref.Name] != ref.Version {
			return ErrUnavailable
		}
		seen[ref.SecretId] = true
		previous = ref.Name
	}
	return nil
}

func uniqueJSONValue(decoder *json.Decoder, depth int) bool {
	if depth > 64 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return true
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok || seen[name] || !uniqueJSONValue(decoder, depth+1) {
				return false
			}
			seen[name] = true
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !uniqueJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}
