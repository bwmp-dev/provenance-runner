//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

func TestCompleteLogExportRejectsWindowsWithoutClaimingOwnerOnlyPermissions(t *testing.T) {
	destination := t.TempDir() + `\complete.log.gz`
	result := execution.FailedResult("windows-export", execution.PhaseExecution, execution.ClassificationWorkloadFailure, "workload_failed", errors.New("original failure"))
	result.CompleteLog = completeLogFromContent(t, []byte("complete log"))
	var stdout, stderr bytes.Buffer
	if exitCode := writeResultAndCompleteLog(&stdout, &stderr, result, destination); exitCode != 2 {
		t.Fatalf("writeResultAndCompleteLog() exit code = %d, want 2", exitCode)
	}
	var emitted execution.Result
	if err := json.Unmarshal(stdout.Bytes(), &emitted); err != nil {
		t.Fatalf("decode structured result: %v", err)
	}
	if emitted.Failure == nil || emitted.Failure.Code != result.Failure.Code {
		t.Fatalf("emitted result = %#v", emitted)
	}
	if !strings.Contains(stderr.String(), "complete-log export requires Linux O_TMPFILE support") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination exists or stat failed unexpectedly: %v", err)
	}
}
