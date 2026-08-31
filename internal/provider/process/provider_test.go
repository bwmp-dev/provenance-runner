package process

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	if result.CompleteLog == nil || len(result.CompleteLog.Data) == 0 {
		t.Fatalf("complete log = %#v", result.CompleteLog)
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
	if result.CompleteLog == nil || len(result.CompleteLog.Data) == 0 {
		t.Fatalf("complete log after timeout = %#v", result.CompleteLog)
	}
}

func TestProviderRemovesPerJobWorkspace(t *testing.T) {
	workspaceRoot := t.TempDir()
	configuration := fmt.Sprintf(`{
		"acknowledgeUnsandboxed":true,
		"command":%q,
		"arguments":["-test.run=TestProcessHelper","--","working-directory"],
		"workspaceRoot":%q,
		"environment":{"PROVENANCE_PROCESS_HELPER":"1"}
	}`, os.Args[0], workspaceRoot)
	job := localjob.Job{
		SchemaVersion: localjob.SchemaVersion,
		ID:            "job/process-workspace",
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
	if !result.Passed() {
		t.Fatalf("result = %#v", result)
	}
	workingDirectory := strings.TrimSpace(result.Logs.Stdout)
	if workingDirectory == "" {
		t.Fatal("working directory output is empty")
	}
	relative, err := filepath.Rel(workspaceRoot, workingDirectory)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
		t.Fatalf("working directory = %q, workspace root = %q, relative = %q, error = %v", workingDirectory, workspaceRoot, relative, err)
	}
	if _, err := os.Stat(workingDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace Stat() error = %v, want not exist", err)
	}
	if _, err := os.Stat(workspaceRoot); err != nil {
		t.Fatalf("workspace root Stat() error = %v", err)
	}
}

func TestProviderProducesSanitizedCompressedEvidence(t *testing.T) {
	configuration := fmt.Sprintf(`{
		"acknowledgeUnsandboxed":true,
		"command":%q,
		"arguments":["-test.run=TestProcessHelper","--","evidence"],
		"redactSecrets":["secret-value"],
		"environment":{"PROVENANCE_PROCESS_HELPER":"1"}
	}`, os.Args[0])
	job := localjob.Job{
		SchemaVersion:  localjob.SchemaVersion,
		ID:             "job/process-evidence",
		Provider:       ProviderName,
		MaxOutputBytes: 4096,
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
	want := "[REDACTED] invalid=�\n"
	if result.Logs == nil || result.Logs.Stdout != want {
		t.Fatalf("logs = %#v, want stdout %q", result.Logs, want)
	}
	if result.CompleteLog == nil || len(result.CompleteLog.Data) == 0 || result.CompleteLog.ContentEncoding != "gzip" {
		t.Fatalf("complete log = %#v", result.CompleteLog)
	}
	reader, err := gzip.NewReader(bytes.NewReader(result.CompleteLog.Data))
	if err != nil {
		t.Fatalf("gzip.NewReader() error = %v", err)
	}
	complete, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if strings.Contains(string(complete), "secret-value") || strings.ContainsRune(string(complete), '\x1b') {
		t.Fatalf("complete log was not sanitized: %q", complete)
	}
	if result.Usage.RawOutputBytes == 0 || result.Usage.CapturedOutputBytes == 0 || result.Usage.CompressedLogBytes != int64(len(result.CompleteLog.Data)) {
		t.Fatalf("usage = %#v", result.Usage)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if bytes.Contains(encoded, result.CompleteLog.Data) {
		t.Fatal("structured result contains compressed log payload")
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
	case "working-directory":
		workingDirectory, err := os.Getwd()
		if err != nil {
			os.Exit(11)
		}
		fmt.Fprint(os.Stdout, workingDirectory)
	case "evidence":
		_, _ = os.Stdout.Write([]byte("\x1b[31msecret-value\x1b[0m invalid="))
		_, _ = os.Stdout.Write([]byte{0xff, '\n'})
	default:
		os.Exit(10)
	}
	os.Exit(0)
}
