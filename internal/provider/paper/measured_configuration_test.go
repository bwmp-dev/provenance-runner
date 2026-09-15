package paper

import "testing"

func TestLegacyConfigurationParserDoesNotAdmitV2(t *testing.T) {
	raw := []byte(`{"apiVersion":"provenance.dev/v2","project":{"name":"Fixture"},"tests":{"startup":{"stabilizationSeconds":1},"console":[]},"resources":{"logBytes":1024}}`)
	if _, _, err := decodeNormalizedConfiguration(raw); err == nil {
		t.Fatal("legacy parser admitted v2")
	}
	if _, _, err := decodeNormalizedConfigurationVersion(raw, true); err != nil {
		t.Fatal("measured parser cannot project v2", err)
	}
	// Projection alone is not complete schema validation or job admission.
}
