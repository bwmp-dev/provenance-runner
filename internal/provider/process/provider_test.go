package process

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
)

func TestProviderRequiresUnsandboxedAcknowledgement(t *testing.T) {
	_, err := New().Resolve(context.Background(), execution.Request{
		Environment: json.RawMessage(`{"command":"example"}`),
		Limits:      execution.Limits{MaxOutputBytes: 1024},
	})
	if err == nil || !strings.Contains(err.Error(), "acknowledgeUnsandboxed=true") {
		t.Fatalf("Resolve() error = %v", err)
	}
}

func TestProviderExecutesAndBoundsOutput(t *testing.T) {
	configuration := fmt.Sprintf(`{
		"acknowledgeUnsandboxed":true,
		"command":%q,
		"arguments":["-test.run=TestProcessHelper","--","output"],
		"environment":{"PROVENANCE_PROCESS_HELPER":"1"}
	}`, os.Args[0])
	job := localjob.Job{
		SchemaVersion:  localjob.SchemaVersion,
		ID:             "job/process-output",
		Provider:       ProviderName,
		MaxOutputBytes: 8,
		Environment:    json.RawMessage(configuration),
	}
	registry, err := execution.NewRegistry(New())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	executor, err := execution.NewExecutor(registry, execution.ExecutorOptions{})
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}

	result := executor.Execute(context.Background(), job)
	if !result.Passed() {
		t.Fatalf("result = %#v", result)
	}
	if result.Logs == nil || !result.Logs.OutputTruncated {
		t.Fatalf("logs = %#v", result.Logs)
	}
	if result.Logs.CapturedBytes != 8 || result.Logs.ObservedBytes <= result.Logs.CapturedBytes {
		t.Fatalf("logs = %#v", result.Logs)
	}
	if result.Cleanup == nil || !result.Cleanup.Succeeded {
		t.Fatalf("cleanup = %#v", result.Cleanup)
	}
}

func TestProviderClassifiesNonzeroExit(t *testing.T) {
	configuration := fmt.Sprintf(`{
		"acknowledgeUnsandboxed":true,
		"command":%q,
		"arguments":["-test.run=TestProcessHelper","--","failure"],
		"environment":{"PROVENANCE_PROCESS_HELPER":"1"}
	}`, os.Args[0])
	job := localjob.Job{
		SchemaVersion: localjob.SchemaVersion,
		ID:            "job/process-failure",
		Provider:      ProviderName,
		Environment:   json.RawMessage(configuration),
	}
	registry, err := execution.NewRegistry(New())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	executor, err := execution.NewExecutor(registry, execution.ExecutorOptions{})
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}

	result := executor.Execute(context.Background(), job)
	if result.Classification != execution.ClassificationWorkloadFailure {
		t.Fatalf("classification = %q, failure = %#v", result.Classification, result.Failure)
	}
	if result.Execution == nil || result.Execution.ExitCode == nil || *result.Execution.ExitCode != 9 {
		t.Fatalf("execution = %#v", result.Execution)
	}
}

func TestProviderHonorsJobTimeout(t *testing.T) {
	configuration := fmt.Sprintf(`{
		"acknowledgeUnsandboxed":true,
		"command":%q,
		"arguments":["-test.run=TestProcessHelper","--","sleep"],
		"environment":{"PROVENANCE_PROCESS_HELPER":"1"}
	}`, os.Args[0])
	job := localjob.Job{
		SchemaVersion:       localjob.SchemaVersion,
		ID:                  "job/process-timeout",
		Provider:            ProviderName,
		TimeoutMilliseconds: 25,
		Environment:         json.RawMessage(configuration),
	}
	registry, err := execution.NewRegistry(New())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	executor, err := execution.NewExecutor(registry, execution.ExecutorOptions{})
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}

	result := executor.Execute(context.Background(), job)
	if result.Classification != execution.ClassificationTimedOut {
		t.Fatalf("classification = %q, failure = %#v", result.Classification, result.Failure)
	}
	if result.Cleanup == nil || !result.Cleanup.Succeeded {
		t.Fatalf("cleanup = %#v", result.Cleanup)
	}
}

func TestProcessHelper(t *testing.T) {
	if os.Getenv("PROVENANCE_PROCESS_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "output":
		fmt.Fprint(os.Stdout, "stdout-data")
		fmt.Fprint(os.Stderr, "stderr-data")
	case "failure":
		fmt.Fprint(os.Stderr, "fixture failed")
		os.Exit(9)
	case "sleep":
		time.Sleep(time.Minute)
	default:
		os.Exit(10)
	}
	os.Exit(0)
}

func TestNormalizeOutputReplacesInvalidUTF8(t *testing.T) {
	got := normalizeOutput([]byte{'a', 0xff, 'b'})
	if got != "a\uFFFDb" {
		t.Fatalf("normalizeOutput() = %q", got)
	}
}
