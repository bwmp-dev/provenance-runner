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

	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/workspace"
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
	WorkspaceRoot          string            `json:"workspaceRoot,omitempty"`
	Environment            map[string]string `json:"environment,omitempty"`
	MaxLineBytes           int64             `json:"maxLineBytes,omitempty"`
	RedactSecrets          []string          `json:"redactSecrets,omitempty"`
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
	if configuration.WorkingDirectory != "" && configuration.WorkspaceRoot != "" {
		return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_environment", errors.New("workingDirectory and workspaceRoot cannot both be set"))
	}
	for key, value := range configuration.Environment {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_environment", fmt.Errorf("environment variable name %q is invalid", key))
		}
		if strings.ContainsRune(value, '\x00') {
			return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_environment", fmt.Errorf("environment variable %q contains a null byte", key))
		}
	}
	evidenceConfig := evidence.Config{
		MaxLineBytes:  configuration.MaxLineBytes,
		MaxTotalBytes: request.Limits.MaxOutputBytes,
		Secrets:       configuration.RedactSecrets,
	}
	if err := evidence.ValidateConfig(evidenceConfig); err != nil {
		return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_evidence_configuration", err)
	}

	return &environment{
		configuration:  configuration,
		evidenceConfig: evidenceConfig,
		jobID:          request.JobID,
	}, nil
}

type environment struct {
	configuration  configuration
	evidenceConfig evidence.Config
	jobID          string
}

func (*environment) Identity() string {
	return fmt.Sprintf("%s/%s/%s", ProviderName, runtime.GOOS, runtime.GOARCH)
}

func (e *environment) Prepare(ctx context.Context) (execution.PreparedEnvironment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	collector, err := evidence.NewCollector(e.evidenceConfig)
	if err != nil {
		return nil, fmt.Errorf("create development process evidence collector: %w", err)
	}

	workingDirectory := e.configuration.WorkingDirectory
	var jobWorkspace *workspace.Workspace
	if workingDirectory == "" {
		manager, err := workspace.NewManager(e.configuration.WorkspaceRoot)
		if err != nil {
			return nil, execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_workspace_root", err)
		}
		jobWorkspace, err = manager.Create(ctx, e.jobID)
		if err != nil {
			return nil, fmt.Errorf("create development process workspace: %w", err)
		}
		workingDirectory = jobWorkspace.Root()
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
		configuration:    e.configuration,
		workingDirectory: workingDirectory,
		workspace:        jobWorkspace,
		evidence:         collector,
	}, nil
}

type preparedEnvironment struct {
	configuration    configuration
	workingDirectory string
	workspace        *workspace.Workspace
	evidence         *evidence.Collector
}

func (e *preparedEnvironment) Execute(ctx context.Context) (execution.ExecutionOutcome, error) {
	command := exec.CommandContext(ctx, e.configuration.Command, e.configuration.Arguments...)
	command.Dir = e.workingDirectory
	command.Env = mergedEnvironment(e.configuration.Environment)
	stdout, err := e.evidence.RawWriter(evidence.StreamStdout)
	if err != nil {
		return execution.ExecutionOutcome{}, err
	}
	stderr, err := e.evidence.RawWriter(evidence.StreamStderr)
	if err != nil {
		return execution.ExecutionOutcome{}, err
	}
	command.Stdout = stdout
	command.Stderr = stderr

	err = command.Run()
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
	bundle, err := e.evidence.Snapshot(ctx)
	if err != nil {
		return execution.CollectedOutput{}, err
	}
	events := make([]execution.StructuredEvent, len(bundle.Events))
	for index, event := range bundle.Events {
		events[index] = execution.StructuredEvent{
			Sequence: event.Sequence,
			Kind:     event.Kind,
			Payload:  append([]byte(nil), event.Payload...),
		}
	}
	return execution.CollectedOutput{
		Stdout:           bundle.Stdout,
		Stderr:           bundle.Stderr,
		CapturedBytes:    bundle.Usage.CapturedBytes,
		ObservedBytes:    bundle.Usage.RawBytesObserved,
		OutputTruncated:  bundle.Usage.OutputTruncated,
		StructuredEvents: events,
		CompleteLog: &execution.CompleteLog{
			ContentType:       bundle.CompleteLog.ContentType,
			ContentEncoding:   bundle.CompleteLog.ContentEncoding,
			SHA256:            bundle.CompleteLog.SHA256,
			UncompressedBytes: bundle.CompleteLog.UncompressedBytes,
			CompressedBytes:   bundle.CompleteLog.CompressedBytes,
			Data:              append([]byte(nil), bundle.CompleteLog.Data...),
		},
		EvidenceUsage: execution.EvidenceUsage{
			RawBytesObserved:     bundle.Usage.RawBytesObserved,
			CapturedBytes:        bundle.Usage.CapturedBytes,
			StructuredEventCount: bundle.Usage.StructuredEventCount,
			StructuredEventBytes: bundle.Usage.StructuredEventBytes,
			CompleteLogBytes:     bundle.Usage.CompleteLogBytes,
			CompressedLogBytes:   bundle.Usage.CompressedLogBytes,
			TruncatedLineCount:   bundle.Usage.TruncatedLineCount,
			OutputTruncated:      bundle.Usage.OutputTruncated,
			EventsTruncated:      bundle.Usage.EventsTruncated,
		},
		StructuredEventError: bundle.StructuredEventError,
	}, nil
}

func (e *preparedEnvironment) Cleanup(ctx context.Context) error {
	if e.workspace == nil {
		return nil
	}
	return e.workspace.Cleanup(ctx)
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
