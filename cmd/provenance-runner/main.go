package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/bwmp-dev/provenance-runner/internal/buildinfo"
	"github.com/bwmp-dev/provenance-runner/internal/enrollment"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/gatewayclient"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	"github.com/bwmp-dev/provenance-runner/internal/provider/gvisor"
)

const maximumJobBytes = 1 << 20

func main() {
	if len(os.Args) > 1 && os.Args[1] == gvisor.SystemdLauncherCommand {
		os.Exit(gvisor.RunSystemdLauncher(os.Args[2:], os.Stderr))
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(runContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runContext(context.Background(), arguments, stdin, stdout, stderr)
}

func runContext(ctx context.Context, arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(arguments) == 2 && arguments[0] == "connect" {
		return runConnect(ctx, arguments[1], stderr)
	}
	if len(arguments) == 2 && arguments[0] == "enroll" {
		return runEnroll(ctx, arguments[1], stderr)
	}
	if len(arguments) == 2 && arguments[0] == "execute" {
		return runExecuteContext(ctx, arguments[1], stdin, stdout, stderr, os.Getenv, registryForLocalExecution)
	}
	if len(arguments) == 4 && arguments[0] == "execute" && arguments[2] == "--complete-log" && arguments[3] != "" {
		return runExecuteWithCompleteLogContext(ctx, arguments[1], arguments[3], stdin, stdout, stderr, os.Getenv, registryForLocalExecution)
	}
	writeUsage(stderr)
	return 2
}

func runEnroll(ctx context.Context, configPath string, stderr io.Writer) int {
	if runtime.GOOS != "linux" {
		fmt.Fprintln(stderr, "enroll runner: enrollment requires Linux owner-only filesystem semantics")
		return 1
	}
	if err := enrollment.Run(ctx, configPath, enrollment.Options{}); err != nil {
		fmt.Fprintf(stderr, "enroll runner: %v\n", err)
		return 1
	}
	return 0
}

type localRegistryFactory func(context.Context, string, environmentLookup) (*providerRegistry, error)

func runExecuteContext(ctx context.Context, jobPath string, stdin io.Reader, stdout, stderr io.Writer, lookup environmentLookup, registryFactory localRegistryFactory) int {
	return runExecuteWithCompleteLogContext(ctx, jobPath, "", stdin, stdout, stderr, lookup, registryFactory)
}

func runExecuteWithCompleteLogContext(ctx context.Context, jobPath, completeLogPath string, stdin io.Reader, stdout, stderr io.Writer, lookup environmentLookup, registryFactory localRegistryFactory) int {
	jobData, err := readJob(jobPath, stdin)
	if err != nil {
		return writeResultAndCompleteLog(stdout, stderr, execution.FailedResult("", execution.PhaseValidation, execution.ClassificationInvalidJob, "job_read_failed", err), completeLogPath)
	}
	job, err := localjob.Decode(jobData)
	if err != nil {
		return writeResultAndCompleteLog(stdout, stderr, execution.FailedResult("", execution.PhaseValidation, execution.ClassificationInvalidJob, "invalid_job", err), completeLogPath)
	}

	registry, err := registryFactory(ctx, job.Provider, lookup)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return writeResultAndCompleteLog(stdout, stderr, execution.FailedResult(job.ID, execution.PhaseValidation, execution.ClassificationCancelled, "job_cancelled", ctx.Err()), completeLogPath)
		}
		return writeResultAndCompleteLog(stdout, stderr, execution.FailedResult(job.ID, execution.PhaseValidation, execution.ClassificationInfrastructureFailure, "runner_initialization_failed", err), completeLogPath)
	}
	defer func() {
		if err := registry.Close(); err != nil {
			fmt.Fprintf(stderr, "release runner instance: %v\n", err)
		}
	}()
	executor, err := execution.NewExecutor(registry.Registry, execution.ExecutorOptions{})
	if err != nil {
		return writeResultAndCompleteLog(stdout, stderr, execution.FailedResult(job.ID, execution.PhaseValidation, execution.ClassificationInfrastructureFailure, "runner_initialization_failed", err), completeLogPath)
	}

	return writeResultAndCompleteLog(stdout, stderr, executor.Execute(ctx, job), completeLogPath)
}

func runConnect(ctx context.Context, configPath string, stderr io.Writer) int {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		fmt.Fprintln(stderr, "connect runner: this alpha advertises and requires linux/amd64")
		return 1
	}
	config, err := gatewayclient.LoadConfig(configPath, buildinfo.Version)
	if err != nil {
		fmt.Fprintf(stderr, "connect runner: %v\n", err)
		return 1
	}
	registry, err := registryForProvider(ctx, "paper", os.Getenv)
	if err != nil {
		fmt.Fprintf(stderr, "connect runner: initialize Paper provider: %v\n", err)
		return 1
	}
	defer func() {
		if err := registry.Close(); err != nil {
			fmt.Fprintf(stderr, "release runner instance: %v\n", err)
		}
	}()
	worker, err := newConnectedWorker(registry)
	if err != nil {
		fmt.Fprintf(stderr, "connect runner: %v\n", err)
		return 1
	}
	client, err := gatewayclient.DialWithWorker(config, worker)
	if err != nil {
		fmt.Fprintf(stderr, "connect runner: %v\n", err)
		return 1
	}
	defer func() {
		if err := client.Close(); err != nil {
			fmt.Fprintf(stderr, "close gateway connection: %v\n", err)
		}
	}()
	if err := client.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "connect runner: %v\n", err)
		return 1
	}
	return 0
}

func writeUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: provenance-runner execute <job.json|->")
	fmt.Fprintln(writer, "       provenance-runner execute <job.json|-> --complete-log <new-path>")
	fmt.Fprintln(writer, "       provenance-runner connect <connect.json>")
	fmt.Fprintln(writer, "       provenance-runner enroll <enrollment.json>")
}

func readJob(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return readBounded(stdin, "stdin")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open job file: %w", err)
	}
	defer file.Close()
	return readBounded(file, "job file")
}

func readBounded(reader io.Reader, source string) ([]byte, error) {
	var buffer bytes.Buffer
	written, err := io.CopyN(&buffer, reader, maximumJobBytes+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	if written > maximumJobBytes {
		return nil, fmt.Errorf("read %s: job exceeds %d bytes", source, maximumJobBytes)
	}
	return buffer.Bytes(), nil
}

func writeResult(writer io.Writer, result execution.Result) int {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		if !errors.Is(err, io.ErrClosedPipe) {
			fmt.Fprintf(os.Stderr, "write result: %v\n", err)
		}
		return 2
	}
	if result.Passed() {
		return 0
	}
	return 1
}
