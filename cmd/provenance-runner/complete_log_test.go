//go:build linux

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
)

func TestRunExportsCompleteLogForPassingExecution(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "complete.log.gz")
	job := completeLogExportJob(t, "pass")
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"execute", "-", "--complete-log", destination}, bytes.NewReader(job), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	result := decodeCompleteLogExportResult(t, stdout.Bytes())
	if !result.Passed() || result.CompleteLog == nil {
		t.Fatalf("result = %#v", result)
	}
	assertExportMatchesResult(t, destination, result, "complete-log-pass")
	if bytes.Contains(stdout.Bytes(), []byte(`"data"`)) {
		t.Fatalf("structured result includes complete-log data: %s", stdout.Bytes())
	}
}

func TestRunExportsCompleteLogForFailedExecution(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "complete.log.gz")
	job := completeLogExportJob(t, "fail")
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"execute", "-", "--complete-log", destination}, bytes.NewReader(job), &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1; stderr = %q", exitCode, stderr.String())
	}
	result := decodeCompleteLogExportResult(t, stdout.Bytes())
	if result.Classification != execution.ClassificationWorkloadFailure || result.Failure == nil {
		t.Fatalf("result = %#v", result)
	}
	assertExportMatchesResult(t, destination, result, "complete-log-failure")
}

func TestRunExportsCompleteLogForTimedOutExecution(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "complete.log.gz")
	job := completeLogExportJob(t, "timeout")
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"execute", "-", "--complete-log", destination}, bytes.NewReader(job), &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1; stderr = %q", exitCode, stderr.String())
	}
	result := decodeCompleteLogExportResult(t, stdout.Bytes())
	if result.Classification != execution.ClassificationTimedOut || result.Failure == nil {
		t.Fatalf("result = %#v", result)
	}
	assertExportMatchesResult(t, destination, result, "complete-log-timeout")
}

func TestRunCompleteLogExportFailurePreservesStructuredResult(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "complete.log.gz")
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	job := completeLogExportJob(t, "pass")
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"execute", "-", "--complete-log", destination}, bytes.NewReader(job), &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	result := decodeCompleteLogExportResult(t, stdout.Bytes())
	if !result.Passed() {
		t.Fatalf("execution result changed after export failure: %#v", result)
	}
	if !strings.Contains(stderr.String(), "export complete log: publish destination:") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	contents, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "existing" {
		t.Fatalf("existing destination changed to %q", contents)
	}
}

func TestRunCompleteLogExportFailsWhenCollectionDidNotProduceLog(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "complete.log.gz")
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"execute", "-", "--complete-log", destination}, strings.NewReader(`{"not":"a job"}`), &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	result := decodeCompleteLogExportResult(t, stdout.Bytes())
	if result.Classification != execution.ClassificationInvalidJob || result.Failure == nil || result.Failure.Code != "invalid_job" {
		t.Fatalf("result = %#v", result)
	}
	if stderr.String() != "export complete log: complete log data is unavailable\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination exists or stat failed unexpectedly: %v", err)
	}
}

func TestRunParsesCompleteLogOnlyForLocalExecute(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
	}{
		{name: "missing path", arguments: []string{"execute", "-", "--complete-log"}},
		{name: "empty path", arguments: []string{"execute", "-", "--complete-log", ""}},
		{name: "option before job", arguments: []string{"execute", "--complete-log", "out.gz", "-"}},
		{name: "unknown option", arguments: []string{"execute", "-", "--output", "out.gz"}},
		{name: "connect option", arguments: []string{"connect", "connect.json", "--complete-log", "out.gz"}},
		{name: "extra argument", arguments: []string{"execute", "-", "--complete-log", "out.gz", "extra"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if exitCode := run(test.arguments, strings.NewReader(""), &stdout, &stderr); exitCode != 2 {
				t.Fatalf("run() exit code = %d, want 2", exitCode)
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "execute <job.json|-> --complete-log <new-path>") {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestExportCompleteLogValidatesMetadataBeforeCreatingDestination(t *testing.T) {
	valid := validCompleteLog([]byte("gzip-payload"))
	tests := []struct {
		name   string
		mutate func(*execution.CompleteLog)
	}{
		{name: "missing log", mutate: func(log *execution.CompleteLog) { *log = execution.CompleteLog{} }},
		{name: "content type", mutate: func(log *execution.CompleteLog) { log.ContentType = "application/gzip" }},
		{name: "content encoding", mutate: func(log *execution.CompleteLog) { log.ContentEncoding = "identity" }},
		{name: "compressed length", mutate: func(log *execution.CompleteLog) { log.CompressedBytes++ }},
		{name: "sha256", mutate: func(log *execution.CompleteLog) { log.SHA256 = strings.Repeat("0", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			log := *valid
			test.mutate(&log)
			destination := filepath.Join(t.TempDir(), "complete.log.gz")
			if err := exportCompleteLog(destination, &log); err == nil {
				t.Fatal("exportCompleteLog() error = nil")
			}
			if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("destination exists or stat failed unexpectedly: %v", err)
			}
		})
	}
}

func TestExportCompleteLogCreatesExactOwnerOnlyFile(t *testing.T) {
	payload := []byte("exact-gzip-payload")
	completeLog := validCompleteLog(payload)
	destination := filepath.Join(t.TempDir(), "complete.log.gz")
	if err := exportCompleteLog(destination, completeLog); err != nil {
		t.Fatalf("exportCompleteLog() error = %v", err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, completeLog.Data) {
		t.Fatalf("destination differs from the exact compressed payload")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(destination)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("destination permissions = %04o, want 0600", info.Mode().Perm())
		}
	}
}

func TestExportCompleteLogRefusesExistingSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "complete.log.gz")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	if err := exportCompleteLog(link, validCompleteLog([]byte("replacement"))); err == nil {
		t.Fatal("exportCompleteLog() error = nil")
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "target" {
		t.Fatalf("symlink target changed to %q", contents)
	}
}

func TestExportCompleteLogDoesNotCreateParentDirectories(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "missing", "parent")
	destination := filepath.Join(directory, "complete.log.gz")
	if err := exportCompleteLog(destination, validCompleteLog([]byte("payload"))); err == nil {
		t.Fatal("exportCompleteLog() error = nil")
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("parent exists or stat failed unexpectedly: %v", err)
	}
}

func TestExportCompleteLogRejectsFilesystemWithoutUnnamedTemporaryFiles(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "complete.log.gz")
	operations := osCompleteLogLinuxOperations
	operations.openTemporary = func(*os.File) (completeLogDestination, error) {
		return nil, errors.New("injected O_TMPFILE rejection")
	}
	err := exportCompleteLogFileWithOperations(destination, validCompleteLog([]byte("payload")).Data, operations)
	if err == nil || !strings.Contains(err.Error(), "create unnamed staging file: injected O_TMPFILE rejection") {
		t.Fatalf("exportCompleteLogFileWithOperations() error = %v", err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination exists or stat failed unexpectedly: %v", err)
	}
}

func TestExportCompleteLogRemovesPartialFilesAfterIOFailure(t *testing.T) {
	tests := []struct {
		name  string
		fault string
	}{
		{name: "write", fault: "write"},
		{name: "sync", fault: "sync"},
		{name: "close", fault: "close"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			destination := filepath.Join(directory, "complete.log.gz")
			operations := osCompleteLogLinuxOperations
			openTemporary := operations.openTemporary
			operations.openTemporary = func(directory *os.File) (completeLogDestination, error) {
				destination, err := openTemporary(directory)
				if err != nil {
					return nil, err
				}
				return &faultingCompleteLogDestination{completeLogDestination: destination, fault: test.fault}, nil
			}
			if err := exportCompleteLogFileWithOperations(destination, validCompleteLog([]byte("payload")).Data, operations); err == nil {
				t.Fatal("exportCompleteLogWithOperations() error = nil")
			}
			if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial destination exists or stat failed unexpectedly: %v", err)
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("staging entries remain after failure: %v", entries)
			}
		})
	}
}

func TestExportCompleteLogPublishesAnchoredFileAfterSuccessfulCloseReplacement(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "complete.log.gz")
	replacementPath := filepath.Join(directory, "replacement-source")
	if err := os.WriteFile(replacementPath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	completeLog := validCompleteLog([]byte("original-complete-log"))
	operations := osCompleteLogLinuxOperations
	var stagingPath string
	operations.openTemporary = func(directory *os.File) (completeLogDestination, error) {
		file, err := os.CreateTemp(directory.Name(), ".named-staging-*")
		if err != nil {
			return nil, err
		}
		stagingPath = file.Name()
		return &replacingCompleteLogDestination{File: file, path: stagingPath, replacementPath: replacementPath}, nil
	}
	operations.publish = func(anchor, directory *os.File, name string) error {
		if _, err := anchor.Seek(0, io.SeekStart); err != nil {
			return err
		}
		published, err := os.OpenFile(filepath.Join(directory.Name(), name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(published, anchor)
		syncErr := published.Sync()
		closeErr := published.Close()
		return errors.Join(copyErr, syncErr, closeErr)
	}

	if err := exportCompleteLogFileWithOperations(destination, completeLog.Data, operations); err != nil {
		t.Fatalf("exportCompleteLogFileWithOperations() error = %v", err)
	}
	published, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(published, completeLog.Data) {
		t.Fatalf("published bytes came from the replacement staging pathname")
	}
	replacement, err := os.ReadFile(stagingPath)
	if err != nil {
		t.Fatalf("read replacement path: %v", err)
	}
	if string(replacement) != "replacement" {
		t.Fatalf("replacement path = %q", replacement)
	}
}

type faultingCompleteLogDestination struct {
	completeLogDestination
	fault string
}

type replacingCompleteLogDestination struct {
	*os.File
	path            string
	replacementPath string
}

func (destination *replacingCompleteLogDestination) Close() error {
	if err := destination.File.Close(); err != nil {
		return err
	}
	if err := os.Remove(destination.path); err != nil {
		return err
	}
	return os.Rename(destination.replacementPath, destination.path)
}

func (destination *faultingCompleteLogDestination) Write(data []byte) (int, error) {
	if destination.fault != "write" {
		return destination.completeLogDestination.Write(data)
	}
	written, err := destination.completeLogDestination.Write(data[:1])
	if err != nil {
		return written, err
	}
	return written, errors.New("injected write failure")
}

func (destination *faultingCompleteLogDestination) Sync() error {
	if destination.fault == "sync" {
		return errors.New("injected sync failure")
	}
	return destination.completeLogDestination.Sync()
}

func (destination *faultingCompleteLogDestination) Close() error {
	err := destination.completeLogDestination.Close()
	if destination.fault == "close" {
		return errors.Join(err, errors.New("injected close failure"))
	}
	return err
}

func validCompleteLog(payload []byte) *execution.CompleteLog {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(payload); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	data := compressed.Bytes()
	digest := sha256.Sum256(data)
	return &execution.CompleteLog{
		ContentType:       completeLogContentType,
		ContentEncoding:   completeLogContentEncoding,
		SHA256:            hex.EncodeToString(digest[:]),
		UncompressedBytes: int64(len(payload)),
		CompressedBytes:   int64(len(data)),
		Data:              append([]byte(nil), data...),
	}
}

func completeLogExportJob(t *testing.T, mode string) []byte {
	t.Helper()
	environment, err := json.Marshal(map[string]any{
		"acknowledgeUnsandboxed": true,
		"command":                os.Args[0],
		"arguments":              []string{"-test.run=^TestCompleteLogExportProcessHelper$", "--", mode},
		"environment":            map[string]string{"PROVENANCE_COMPLETE_LOG_HELPER": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	timeout := int64(5_000)
	if mode == "timeout" {
		timeout = 50
	}
	job, err := json.Marshal(localjob.Job{
		SchemaVersion:       localjob.SchemaVersion,
		ID:                  "complete-log-" + mode,
		Provider:            "development-process",
		TimeoutMilliseconds: timeout,
		Environment:         environment,
	})
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func decodeCompleteLogExportResult(t *testing.T, data []byte) execution.Result {
	t.Helper()
	var result execution.Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v; output = %q", err, data)
	}
	return result
}

func assertExportMatchesResult(t *testing.T, path string, result execution.Result, expected string) {
	t.Helper()
	exported, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(exported)
	if result.CompleteLog.CompressedBytes != int64(len(exported)) || result.CompleteLog.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("complete log metadata = %#v, exported bytes = %d, SHA-256 = %x", result.CompleteLog, len(exported), digest)
	}
	reader, err := gzip.NewReader(bytes.NewReader(exported))
	if err != nil {
		t.Fatal(err)
	}
	uncompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(uncompressed, []byte(expected)) {
		t.Fatalf("complete log = %q, want content %q", uncompressed, expected)
	}
}

func TestCompleteLogExportProcessHelper(t *testing.T) {
	if os.Getenv("PROVENANCE_COMPLETE_LOG_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "pass":
		fmt.Fprintln(os.Stdout, "complete-log-pass")
	case "fail":
		fmt.Fprintln(os.Stderr, "complete-log-failure")
		os.Exit(9)
	case "timeout":
		fmt.Fprintln(os.Stdout, "complete-log-timeout")
		time.Sleep(time.Minute)
	default:
		os.Exit(10)
	}
}
