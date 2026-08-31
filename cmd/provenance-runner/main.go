package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
)

const maximumJobBytes = 1 << 20

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(arguments) != 2 || arguments[0] != "execute" {
		fmt.Fprintln(stderr, "usage: provenance-runner execute <job.json|->")
		return 2
	}

	jobData, err := readJob(arguments[1], stdin)
	if err != nil {
		return writeResult(stdout, execution.FailedResult("", execution.PhaseValidation, execution.ClassificationInvalidJob, "job_read_failed", err))
	}
	job, err := localjob.Decode(jobData)
	if err != nil {
		return writeResult(stdout, execution.FailedResult("", execution.PhaseValidation, execution.ClassificationInvalidJob, "invalid_job", err))
	}

	registry, err := registryForProvider(context.Background(), job.Provider, os.Getenv)
	if err != nil {
		return writeResult(stdout, execution.FailedResult(job.ID, execution.PhaseValidation, execution.ClassificationInfrastructureFailure, "runner_initialization_failed", err))
	}
	executor, err := execution.NewExecutor(registry, execution.ExecutorOptions{})
	if err != nil {
		return writeResult(stdout, execution.FailedResult(job.ID, execution.PhaseValidation, execution.ClassificationInfrastructureFailure, "runner_initialization_failed", err))
	}

	return writeResult(stdout, executor.Execute(context.Background(), job))
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
