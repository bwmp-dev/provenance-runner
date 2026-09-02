package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
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
	if !strings.Contains(stderr.String(), "connect <connect.json>") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "enroll <enrollment.json>") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunFailsPaperInitializationBeforeExecutionWhenTrustedPinIsMissing(t *testing.T) {
	t.Setenv("PROVENANCE_PAPER_PROBE_URI", "")
	job := `{"schemaVersion":"provenance.local-job/v1alpha1","id":"paper-job","provider":"paper","environment":{}}`
	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"execute", "-"}, strings.NewReader(job), &stdout, &stderr); exitCode != 1 {
		t.Fatalf("run() exit code = %d", exitCode)
	}
	var result execution.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Failure == nil || result.Failure.Code != "runner_initialization_failed" || result.Execution != nil || result.Environment != nil {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunExecutePassesCancellationToProviderInitialization(t *testing.T) {
	type contextKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "signal-context"))
	started := make(chan struct{})
	completed := make(chan struct {
		code   int
		stdout string
	}, 1)
	job := `{"schemaVersion":"provenance.local-job/v1alpha1","id":"paper-job","provider":"paper","environment":{}}`
	factory := func(factoryContext context.Context, _ string, _ environmentLookup) (*providerRegistry, error) {
		if factoryContext.Value(contextKey{}) != "signal-context" {
			return nil, fmt.Errorf("provider received a different context")
		}
		close(started)
		<-factoryContext.Done()
		return nil, factoryContext.Err()
	}
	go func() {
		var stdout, stderr bytes.Buffer
		code := runExecuteContext(ctx, "-", strings.NewReader(job), &stdout, &stderr, os.Getenv, factory)
		completed <- struct {
			code   int
			stdout string
		}{code: code, stdout: stdout.String()}
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("provider initialization did not start")
	}
	cancel()
	select {
	case result := <-completed:
		if result.code != 1 {
			t.Fatalf("exit code = %d, want 1", result.code)
		}
		var executionResult execution.Result
		if err := json.Unmarshal([]byte(result.stdout), &executionResult); err != nil {
			t.Fatal(err)
		}
		if executionResult.Classification != execution.ClassificationCancelled || executionResult.Failure == nil || executionResult.Failure.Code != "job_cancelled" {
			t.Fatalf("result = %#v", executionResult)
		}
	case <-time.After(time.Second):
		t.Fatal("provider initialization did not observe cancellation")
	}
}

func TestRunContextCancelsDevelopmentProcessExecution(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	environment, err := json.Marshal(map[string]any{
		"acknowledgeUnsandboxed": true,
		"command":                os.Args[0],
		"arguments":              []string{"-test.run=^TestRunContextProcessHelper$", "--", marker},
		"environment":            map[string]string{"PROVENANCE_RUN_CONTEXT_HELPER": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := json.Marshal(localjob.Job{
		SchemaVersion:       localjob.SchemaVersion,
		ID:                  "process-cancellation",
		Provider:            "development-process",
		TimeoutMilliseconds: 2_000,
		Environment:         environment,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	completed := make(chan struct {
		code   int
		stdout string
	}, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		code := runContext(ctx, []string{"execute", "-"}, bytes.NewReader(job), &stdout, &stderr)
		completed <- struct {
			code   int
			stdout string
		}{code: code, stdout: stdout.String()}
	}()

	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("development process did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case result := <-completed:
		if result.code != 1 {
			t.Fatalf("exit code = %d, want 1", result.code)
		}
		var executionResult execution.Result
		if err := json.Unmarshal([]byte(result.stdout), &executionResult); err != nil {
			t.Fatal(err)
		}
		if executionResult.Classification != execution.ClassificationCancelled || executionResult.Failure == nil || executionResult.Failure.Code != "job_cancelled" {
			t.Fatalf("result = %#v", executionResult)
		}
		if executionResult.Cleanup == nil || !executionResult.Cleanup.Succeeded {
			t.Fatalf("cleanup = %#v", executionResult.Cleanup)
		}
	case <-time.After(time.Second):
		t.Fatal("development process execution did not observe cancellation")
	}
}

func TestRunContextProcessHelper(t *testing.T) {
	if os.Getenv("PROVENANCE_RUN_CONTEXT_HELPER") != "1" {
		return
	}
	marker := os.Args[len(os.Args)-1]
	if err := os.WriteFile(marker, []byte("started"), 0o600); err != nil {
		os.Exit(11)
	}
	time.Sleep(time.Minute)
}
