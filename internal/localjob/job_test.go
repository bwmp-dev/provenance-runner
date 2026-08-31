package localjob

import (
	"fmt"
	"testing"
	"time"
)

func TestDecodeAppliesDefaults(t *testing.T) {
	job, err := Decode([]byte(`{
		"schemaVersion":"provenance.local-job/v1alpha1",
		"id":"job/123",
		"provider":"development-process",
		"environment":{"command":"example"}
	}`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if job.Timeout() != DefaultTimeout {
		t.Fatalf("Timeout() = %v, want %v", job.Timeout(), DefaultTimeout)
	}
	if job.OutputLimit() != DefaultMaxOutputBytes {
		t.Fatalf("OutputLimit() = %d, want %d", job.OutputLimit(), DefaultMaxOutputBytes)
	}
}

func TestDecodePreservesPhaseTimeouts(t *testing.T) {
	job, err := Decode([]byte(`{
		"schemaVersion":"provenance.local-job/v1alpha1",
		"id":"job/123",
		"provider":"paper",
		"preparationTimeoutMilliseconds":120000,
		"timeoutMilliseconds":60000,
		"gracefulShutdownTimeoutMilliseconds":30000,
		"environment":{}
	}`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !job.UsesPhaseTimeouts() || job.PreparationTimeout() != 2*time.Minute || job.Timeout() != time.Minute || job.GracefulShutdownTimeout() != 30*time.Second {
		t.Fatalf("phase timeouts = %#v", job)
	}
}

func TestDecodeRejectsInvalidJobs(t *testing.T) {
	tests := map[string]string{
		"unknown field":       `{"schemaVersion":"provenance.local-job/v1alpha1","id":"job","provider":"p","environment":{},"extra":true}`,
		"trailing JSON":       `{"schemaVersion":"provenance.local-job/v1alpha1","id":"job","provider":"p","environment":{}} {}`,
		"wrong version":       `{"schemaVersion":"v1","id":"job","provider":"p","environment":{}}`,
		"invalid id":          `{"schemaVersion":"provenance.local-job/v1alpha1","id":"job space","provider":"p","environment":{}}`,
		"missing environment": `{"schemaVersion":"provenance.local-job/v1alpha1","id":"job","provider":"p"}`,
		"timeout too large":   fmt.Sprintf(`{"schemaVersion":"provenance.local-job/v1alpha1","id":"job","provider":"p","timeoutMilliseconds":%d,"environment":{}}`, (time.Hour + time.Millisecond).Milliseconds()),
		"preparation timeout without graceful timeout": `{"schemaVersion":"provenance.local-job/v1alpha1","id":"job","provider":"p","preparationTimeoutMilliseconds":1000,"environment":{}}`,
		"output too large": fmt.Sprintf(`{"schemaVersion":"provenance.local-job/v1alpha1","id":"job","provider":"p","maxOutputBytes":%d,"environment":{}}`, MaximumOutputBytes+1),
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(input)); err == nil {
				t.Fatal("Decode() error = nil")
			}
		})
	}
}
