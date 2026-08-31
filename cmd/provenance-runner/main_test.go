package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

func TestRunReturnsStructuredInvalidJobResult(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"execute", "-"}, strings.NewReader(`{"not":"a job"}`), &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1; stderr = %q", exitCode, stderr.String())
	}

	var result execution.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v; output = %q", err, stdout.String())
	}
	if result.Classification != execution.ClassificationInvalidJob || result.Failure == nil {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunRejectsOversizedStdin(t *testing.T) {
	var stdout, stderr bytes.Buffer
	input := strings.NewReader(strings.Repeat("x", maximumJobBytes+1))
	exitCode := run([]string{"execute", "-"}, input, &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}

	var result execution.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Failure == nil || result.Failure.Code != "job_read_failed" {
		t.Fatalf("failure = %#v", result.Failure)
	}
}

func TestRunPrintsUsageForUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"unknown"}, strings.NewReader(""), &stdout, &stderr); exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
