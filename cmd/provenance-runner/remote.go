package main

import (
	"context"
	"errors"
	"sync"

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
	registry         *execution.Registry
	adapter          remoteJobAdapter
	measuredEndpoint string
	admission        sync.Mutex
	cleanupFailed    bool
	none             *connectedWorker
}

func (w *connectedWorker) SupportsTestSecretSource() bool {
	if w == nil || w.measuredEndpoint != "" {
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
	if !w.admission.TryLock() {
		return execution.FailedResult(specification.GetLease().GetJobId(), execution.PhasePreparation, execution.ClassificationInfrastructureFailure, "worker_busy", errors.New("worker already owns a session"))
	}
	defer w.admission.Unlock()
	if w.cleanupFailed {
		return execution.FailedResult(specification.GetLease().GetJobId(), execution.PhaseCleanup, execution.ClassificationInfrastructureFailure, "worker_cleanup_unconfirmed", errors.New("worker admission stopped after failed cleanup"))
	}
	if w.measuredEndpoint != "" {
		if v2 && specification.GetEffectivePolicy().GetNetworkV2() != nil && specification.GetEffectivePolicy().GetNetworkV2().GetMode() == runnerv1.NetworkMode_NETWORK_MODE_NONE {
			if w.none == nil {
				return execution.FailedResult(specification.GetLease().GetJobId(), execution.PhaseValidation, execution.ClassificationInvalidJob, "isolated_none_provider_required", errors.New("no-network v2 provider is not provisioned"))
			}
			result := w.none.ExecuteV2(ctx, specification, beforeExecute)
			if result.Cleanup != nil && !result.Cleanup.Succeeded {
				w.cleanupFailed = true
			}
			return result
		}
		provider, ok := w.adapter.(interface {
			ExecuteMeasured(context.Context, *runnerv1.JobSpecification, string, func(context.Context, execution.ExecutionStart) error) execution.Result
		})
		if !v2 || !ok {
			return execution.FailedResult(specification.GetLease().GetJobId(), execution.PhaseValidation, execution.ClassificationInvalidJob, "measured_v2_required", errors.New("measured worker requires separately admitted v2 execution"))
		}
		result := provider.ExecuteMeasured(ctx, specification, w.measuredEndpoint, beforeExecute)
		if result.Cleanup != nil && !result.Cleanup.Succeeded {
			w.cleanupFailed = true
		}
		return result
	}
	adapt := w.adapter.AdaptJob
	if v2 && specification.GetEffectivePolicy().GetNetworkV2() != nil {
		provider, ok := w.adapter.(interface {
			AdaptNoNetworkV2(*runnerv1.JobSpecification) (localjob.Job, error)
		})
		if !ok {
			return execution.FailedResult(specification.GetLease().GetJobId(), execution.PhaseValidation, execution.ClassificationInvalidJob, "isolated_none_v2_required", errors.New("no-network v2 adapter unavailable"))
		}
		adapt = provider.AdaptNoNetworkV2
	}
	job, err := adapt(specification)
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
	if result.Cleanup != nil && !result.Cleanup.Succeeded {
		w.cleanupFailed = true
	}
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
	result := &connectedWorker{registry: registry.Registry, adapter: adapter, measuredEndpoint: registry.measuredEndpoint}
	if registry.none != nil {
		var err error
		result.none, err = newConnectedWorker(registry.none)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
