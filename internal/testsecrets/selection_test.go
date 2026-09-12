package testsecrets

import (
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"strings"
	"testing"
)

func TestImmutableSecretSelectionMatchesConfiguration(t *testing.T) {
	job := &runnerv1.JobSpecification{NormalizedConfigurationJson: []byte(`{"tests":{"secrets":{"token":1}}}`), TestSecrets: []*runnerv1.TestSecretReference{{Name: "token", Version: 1, SecretId: "70000000-0000-0000-0000-000000000001"}}}
	if err := ValidateSelection(job); err != nil {
		t.Fatal(err)
	}
	for _, config := range []string{
		`{"tests":{"secrets":{"token":2}}}`, `{"tests":{"secrets":{"token":1.5}}}`, `{"tests":{"secrets":{"token":"1"}}}`,
		`{"tests":{"secrets":{"token":1,"token":1}}}`, `{"tests":{"secrets":{"token":1},"secrets":{"token":1}}}`,
		`{"tests":{"secrets":{"token":1}},"tests":{"secrets":{"token":1}}}`, `{"tests":{"secrets":{"token":1,"other":1}}}`, `{"tests":{}}`,
	} {
		job.NormalizedConfigurationJson = []byte(config)
		if ValidateSelection(job) == nil {
			t.Fatal("invalid metadata selection accepted")
		}
	}
	job.NormalizedConfigurationJson = []byte(`{"tests":{"secrets":{"token":1}}}`)
	job.TestSecrets = nil
	if ValidateSelection(job) == nil {
		t.Fatal("missing references accepted")
	}
	job.NormalizedConfigurationJson = []byte(`{"tests":{}}`)
	if err := ValidateSelection(job); err != nil {
		t.Fatal("empty selection refused")
	}
	for _, configuration := range []string{`null`, `[]`, `{"tests":null}`, `{"tests":{"secrets":null}}`, strings.Repeat(`{"nested":`, 70) + `null` + strings.Repeat(`}`, 70)} {
		job.NormalizedConfigurationJson = []byte(configuration)
		if ValidateSelection(job) == nil {
			t.Fatal("invalid shape or depth accepted")
		}
	}
}

func TestSelectionRejectsInvalidImmutableReferenceMetadata(t *testing.T) {
	for _, mode := range []string{"zero-version", "large-version", "unsafe-name", "zero-id", "noncanonical-id", "unknown-fields"} {
		t.Run(mode, func(t *testing.T) {
			ref := &runnerv1.TestSecretReference{Name: "token", Version: 1, SecretId: "70000000-0000-0000-0000-000000000001"}
			job := &runnerv1.JobSpecification{NormalizedConfigurationJson: []byte(`{"tests":{"secrets":{"token":1}}}`), TestSecrets: []*runnerv1.TestSecretReference{ref}}
			switch mode {
			case "zero-version":
				ref.Version = 0
			case "large-version":
				ref.Version = 9007199254740992
			case "unsafe-name":
				ref.Name = "../token"
			case "zero-id":
				ref.SecretId = "00000000-0000-0000-0000-000000000000"
			case "noncanonical-id":
				ref.SecretId = "A0000000-0000-0000-0000-000000000001"
			case "unknown-fields":
				ref.ProtoReflect().SetUnknown([]byte{0x78, 1})
			}
			if ValidateSelection(job) == nil {
				t.Fatal("invalid reference accepted")
			}
		})
	}
}

func FuzzSecretSelectionBoundedJSON(f *testing.F) {
	for _, seed := range []string{`{}`, `{"tests":{"secrets":{}}}`, `{"tests":{"secrets":{"token":1,"token":2}}}`, `null`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ValidateSelection(&runnerv1.JobSpecification{NormalizedConfigurationJson: data})
	})
}
