package main

import (
	"context"
	"errors"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

type remoteJobAdapter interface {
	AdaptJob(*runnerv1.JobSpecification) (localjob.Job, error)
}

type connectedWorker struct {
	registry *execution.Registry
	adapter  remoteJobAdapter
}

func (w *connectedWorker) Execute(ctx context.Context, specification *runnerv1.JobSpecification, beforeExecute func(context.Context, execution.ExecutionStart) error) execution.Result {
	job, err := w.adapter.AdaptJob(specification)
	if err != nil {
		return execution.FailedResult(specification.GetLease().GetJobId(), execution.PhaseValidation, execution.ClassificationInvalidJob, "remote_job_adaptation_failed", err)
	}
	executor, err := execution.NewExecutor(w.registry, execution.ExecutorOptions{BeforeExecute: beforeExecute})
	if err != nil {
		return execution.FailedResult(job.ID, execution.PhaseValidation, execution.ClassificationInfrastructureFailure, "runner_initialization_failed", err)
	}
	return executor.Execute(ctx, job)
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
