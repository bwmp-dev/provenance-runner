package process

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

const ProviderName = "development-process"

type Provider struct{}

func New() *Provider {
	return &Provider{}
}

func (*Provider) Name() string {
	return ProviderName
}

type configuration struct {
	AcknowledgeUnsandboxed bool              `json:"acknowledgeUnsandboxed"`
	Command                string            `json:"command"`
	Arguments              []string          `json:"arguments,omitempty"`
	WorkingDirectory       string            `json:"workingDirectory,omitempty"`
	Environment            map[string]string `json:"environment,omitempty"`
}

func (*Provider) Resolve(_ context.Context, request execution.Request) (execution.Environment, error) {
	decoder := json.NewDecoder(bytes.NewReader(request.Environment))
	decoder.DisallowUnknownFields()

	var configuration configuration
	if err := decoder.Decode(&configuration); err != nil {
		return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_environment", fmt.Errorf("decode development process environment: %w", err))
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_environment", errors.New("multiple environment JSON values are not allowed"))
		}
		return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_environment", fmt.Errorf("decode trailing environment data: %w", err))
	}
	if !configuration.AcknowledgeUnsandboxed {
		return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "unsandboxed_execution_not_acknowledged", errors.New("development-process requires acknowledgeUnsandboxed=true"))
	}
	if strings.TrimSpace(configuration.Command) == "" {
		return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_environment", errors.New("command is required"))
	}
	for key, value := range configuration.Environment {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_environment", fmt.Errorf("environment variable name %q is invalid", key))
		}
		if strings.ContainsRune(value, '\x00') {
			return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_environment", fmt.Errorf("environment variable %q contains a null byte", key))
		}
	}

	return &environment{
		configuration: configuration,
		outputLimit:   request.Limits.MaxOutputBytes,
	}, nil
}

type environment struct {
	configuration configuration
	outputLimit   int64
}

func (*environment) Identity() string {
	return fmt.Sprintf("%s/%s/%s", ProviderName, runtime.GOOS, runtime.GOARCH)
}

func (e *environment) Prepare(ctx context.Context) (execution.PreparedEnvironment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	workingDirectory := e.configuration.WorkingDirectory
	ownedWorkingDirectory := false
	if workingDirectory == "" {
		var err error
		workingDirectory, err = os.MkdirTemp("", "provenance-runner-")
		if err != nil {
			return nil, fmt.Errorf("create development process workspace: %w", err)
		}
		ownedWorkingDirectory = true
	} else {
		absoluteDirectory, err := filepath.Abs(workingDirectory)
		if err != nil {
			return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_working_directory", fmt.Errorf("resolve working directory: %w", err))
		}
		info, err := os.Stat(absoluteDirectory)
		if err != nil {
			return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_working_directory", fmt.Errorf("inspect working directory: %w", err))
		}
		if !info.IsDir() {
			return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_working_directory", errors.New("working directory is not a directory"))
		}
		workingDirectory = absoluteDirectory
	}

	return &preparedEnvironment{
		configuration:         e.configuration,
		workingDirectory:      workingDirectory,
		ownedWorkingDirectory: ownedWorkingDirectory,
		capture:               newOutputCapture(e.outputLimit),
	}, nil
}

type preparedEnvironment struct {
	configuration         configuration
	workingDirectory      string
	ownedWorkingDirectory bool
	capture               *outputCapture
}

func (e *preparedEnvironment) Execute(ctx context.Context) (execution.ExecutionOutcome, error) {
	command := exec.CommandContext(ctx, e.configuration.Command, e.configuration.Arguments...)
	command.Dir = e.workingDirectory
	command.Env = mergedEnvironment(e.configuration.Environment)
	command.Stdout = e.capture.writer(true)
	command.Stderr = e.capture.writer(false)

	err := command.Run()
	var exitCode *int
	if command.ProcessState != nil {
		code := command.ProcessState.ExitCode()
		exitCode = &code
	}
	outcome := execution.ExecutionOutcome{ExitCode: exitCode}
	if err == nil {
		return outcome, nil
	}
	if ctx.Err() != nil {
		return outcome, ctx.Err()
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		outcome.Failure = execution.NewFailure(execution.ClassificationWorkloadFailure, "process_exit_nonzero", fmt.Sprintf("process exited with code %d", exitError.ExitCode()))
		return outcome, nil
	}
	return outcome, fmt.Errorf("run development process: %w", err)
}

func (e *preparedEnvironment) Collect(ctx context.Context) (execution.CollectedOutput, error) {
	if err := ctx.Err(); err != nil {
		return execution.CollectedOutput{}, err
	}
	stdout, stderr, captured, observed, truncated := e.capture.collect()
	return execution.CollectedOutput{
		Stdout:          stdout,
		Stderr:          stderr,
		CapturedBytes:   captured,
		ObservedBytes:   observed,
		OutputTruncated: truncated,
	}, nil
}

func (e *preparedEnvironment) Cleanup(ctx context.Context) error {
	if !e.ownedWorkingDirectory {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.RemoveAll(e.workingDirectory); err != nil {
		return fmt.Errorf("remove development process workspace: %w", err)
	}
	return nil
}

func mergedEnvironment(overrides map[string]string) []string {
	environment := append([]string(nil), os.Environ()...)
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		environment = append(environment, key+"="+overrides[key])
	}
	return environment
}
