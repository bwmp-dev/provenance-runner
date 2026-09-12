package main

import (
	"context"
	"errors"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

type remoteJobAdapter interface {
	AdaptJob(*runnerv1.JobSpecification) (localjob.Job, error)
}

type connectedWorker struct {
	registry *execution.Registry
	adapter  remoteJobAdapter
}

func (w *connectedWorker) SupportsTestSecretSource() bool {
	if w == nil {
		return false
	}
	provider, ok := w.adapter.(interface{ SupportsTestSecretSource() bool })
	return ok && provider.SupportsTestSecretSource()
}

func (w *connectedWorker) Execute(ctx context.Context, specification *runnerv1.JobSpecification, beforeExecute func(context.Context, execution.ExecutionStart) error) execution.Result {
	return w.execute(ctx, specification, beforeExecute, false)
}

// ExecuteV2 is only for an admitted v2 job. The supervisor must opt in explicitly;
// ordinary Execute retains v1 semantics for existing callers and replay.
func (w *connectedWorker) ExecuteV2(ctx context.Context, specification *runnerv1.JobSpecification, beforeExecute func(context.Context, execution.ExecutionStart) error) execution.Result {
	return w.execute(ctx, specification, beforeExecute, true)
}

func (w *connectedWorker) execute(ctx context.Context, specification *runnerv1.JobSpecification, beforeExecute func(context.Context, execution.ExecutionStart) error, v2 bool) execution.Result {
	job, err := w.adapter.AdaptJob(specification)
	if err != nil {
		return execution.FailedResult(specification.GetLease().GetJobId(), execution.PhaseValidation, execution.ClassificationInvalidJob, "remote_job_adaptation_failed", err)
	}
	buildContext := terminalevidence.NewContext
	if v2 {
		buildContext = terminalevidence.NewContextV2
	}
	proofContext, err := buildContext(specification)
	if err != nil {
		return execution.FailedResult(specification.GetLease().GetJobId(), execution.PhaseValidation, execution.ClassificationInvalidJob, "terminal_evidence_context_invalid", terminalevidence.ErrInvalid)
	}
	executor, err := execution.NewExecutor(w.registry, execution.ExecutorOptions{BeforeExecute: beforeExecute, TerminalEvidenceV2: v2})
	if err != nil {
		return execution.FailedResult(job.ID, execution.PhaseValidation, execution.ClassificationInfrastructureFailure, "runner_initialization_failed", err)
	}
	result := executor.Execute(ctx, job)
	result.TerminalContext = proofContext
	return result
}

func newConnectedWorker(registry *providerRegistry) (*connectedWorker, error) {
	if registry == nil || registry.Registry == nil {
		return nil, errors.New("remote worker registry is required")
	}
	provider, exists := registry.Provider(paper.ProviderName)
	if !exists {
		return nil, errors.New("Paper provider is not registered")
	}
	adapter, ok := provider.(remoteJobAdapter)
	if !ok {
		return nil, errors.New("Paper provider does not implement remote job adaptation")
	}
	return &connectedWorker{registry: registry.Registry, adapter: adapter}, nil
}
