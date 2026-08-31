package execution

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/localjob"
)

const (
	defaultCollectionTimeout = 5 * time.Second
	defaultCleanupTimeout    = 10 * time.Second
)

type Executor struct {
	registry          *Registry
	collectionTimeout time.Duration
	cleanupTimeout    time.Duration
}

type ExecutorOptions struct {
	CollectionTimeout time.Duration
	CleanupTimeout    time.Duration
}

func NewExecutor(registry *Registry, options ExecutorOptions) (*Executor, error) {
	if registry == nil {
		return nil, errors.New("create executor: registry is nil")
	}
	if options.CollectionTimeout < 0 {
		return nil, errors.New("create executor: collection timeout cannot be negative")
	}
	if options.CleanupTimeout < 0 {
		return nil, errors.New("create executor: cleanup timeout cannot be negative")
	}
	if options.CollectionTimeout == 0 {
		options.CollectionTimeout = defaultCollectionTimeout
	}
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = defaultCleanupTimeout
	}
	return &Executor{
		registry:          registry,
		collectionTimeout: options.CollectionTimeout,
		cleanupTimeout:    options.CleanupTimeout,
	}, nil
}

func (e *Executor) Execute(parent context.Context, job localjob.Job) Result {
	startedAt := time.Now().UTC()
	result := Result{
		SchemaVersion:  ResultSchemaVersion,
		JobID:          job.ID,
		Status:         "passed",
		Classification: ClassificationPassed,
		Phase:          PhaseValidation,
		StartedAt:      startedAt,
	}

	if err := job.Validate(); err != nil {
		setFailure(&result, PhaseValidation, NewFailure(ClassificationInvalidJob, "invalid_job", err.Error()))
		return finishResult(result)
	}

	provider, exists := e.registry.Provider(job.Provider)
	if !exists {
		setFailure(&result, PhaseResolution, NewFailure(ClassificationInvalidJob, "provider_not_found", fmt.Sprintf("provider %q is not registered", job.Provider)))
		return finishResult(result)
	}

	runContext, cancelRun := context.WithTimeout(parent, job.Timeout())
	defer cancelRun()

	result.Phase = PhaseResolution
	environment, err := provider.Resolve(runContext, Request{
		JobID:       job.ID,
		Environment: job.Environment,
		Limits:      Limits{MaxOutputBytes: job.OutputLimit()},
	})
	if err != nil {
		setFailure(&result, PhaseResolution, classifyError(parent, runContext, "provider_resolution_failed", err))
		return finishResult(result)
	}
	if failure := contextFailure(parent, runContext); failure != nil {
		setFailure(&result, PhaseResolution, failure)
		return finishResult(result)
	}
	if environment == nil {
		setFailure(&result, PhaseResolution, NewFailure(ClassificationInfrastructureFailure, "provider_returned_no_environment", "provider returned a nil environment"))
		return finishResult(result)
	}
	result.Environment = &EnvironmentResult{Provider: provider.Name(), Identity: environment.Identity()}

	result.Phase = PhasePreparation
	prepared, prepareErr := environment.Prepare(runContext)
	if prepareErr != nil {
		setFailure(&result, PhasePreparation, classifyError(parent, runContext, "environment_preparation_failed", prepareErr))
	}
	if prepared == nil {
		if prepareErr == nil {
			setFailure(&result, PhasePreparation, NewFailure(ClassificationInfrastructureFailure, "provider_returned_no_prepared_environment", "provider returned a nil prepared environment"))
		}
		return finishResult(result)
	}

	if result.Failure == nil {
		if failure := contextFailure(parent, runContext); failure != nil {
			setFailure(&result, PhasePreparation, failure)
		} else {
			executePrepared(parent, runContext, prepared, &result)
		}
	}

	collectPrepared(parent, prepared, e.collectionTimeout, &result)
	cleanupPrepared(parent, prepared, e.cleanupTimeout, &result)
	return finishResult(result)
}

func executePrepared(parent, runContext context.Context, prepared PreparedEnvironment, result *Result) {
	result.Phase = PhaseExecution
	outcome, err := prepared.Execute(runContext)
	result.Execution = &ExecutionResult{ExitCode: outcome.ExitCode}
	if err != nil {
		setFailure(result, PhaseExecution, classifyError(parent, runContext, "environment_execution_failed", err))
		return
	}
	if failure := contextFailure(parent, runContext); failure != nil {
		setFailure(result, PhaseExecution, failure)
		return
	}
	if outcome.Failure != nil {
		setFailure(result, PhaseExecution, outcome.Failure)
	}
}

func collectPrepared(parent context.Context, prepared PreparedEnvironment, timeout time.Duration, result *Result) {
	collectionContext, cancelCollection := detachedTimeout(parent, timeout)
	defer cancelCollection()

	output, err := prepared.Collect(collectionContext)
	result.Logs = &LogsResult{
		Stdout:          output.Stdout,
		Stderr:          output.Stderr,
		CapturedBytes:   output.CapturedBytes,
		ObservedBytes:   output.ObservedBytes,
		OutputTruncated: output.OutputTruncated,
	}
	result.StructuredEvents = append([]StructuredEvent(nil), output.StructuredEvents...)
	for index := range result.StructuredEvents {
		result.StructuredEvents[index].Payload = append([]byte(nil), result.StructuredEvents[index].Payload...)
	}
	if output.CompleteLog != nil {
		completeLog := *output.CompleteLog
		completeLog.Data = append([]byte(nil), output.CompleteLog.Data...)
		result.CompleteLog = &completeLog
	}
	result.Usage.RawOutputBytes = output.EvidenceUsage.RawBytesObserved
	result.Usage.CapturedOutputBytes = output.EvidenceUsage.CapturedBytes
	result.Usage.StructuredEventCount = output.EvidenceUsage.StructuredEventCount
	result.Usage.StructuredEventBytes = output.EvidenceUsage.StructuredEventBytes
	result.Usage.CompleteLogBytes = output.EvidenceUsage.CompleteLogBytes
	result.Usage.CompressedLogBytes = output.EvidenceUsage.CompressedLogBytes
	result.Usage.TruncatedLineCount = output.EvidenceUsage.TruncatedLineCount
	result.Usage.OutputTruncated = output.EvidenceUsage.OutputTruncated
	result.Usage.StructuredEventsTruncated = output.EvidenceUsage.EventsTruncated
	if err != nil {
		result.Logs.Error = err.Error()
		if result.Failure == nil {
			setFailure(result, PhaseCollection, classifyDetachedError(collectionContext, "output_collection_failed", err))
		}
	}
}

func cleanupPrepared(parent context.Context, prepared PreparedEnvironment, timeout time.Duration, result *Result) {
	cleanupContext, cancelCleanup := detachedTimeout(parent, timeout)
	defer cancelCleanup()

	startedAt := time.Now()
	err := prepared.Cleanup(cleanupContext)
	cleanup := &CleanupResult{
		Attempted:            true,
		Succeeded:            err == nil,
		DurationMilliseconds: time.Since(startedAt).Milliseconds(),
	}
	if err != nil {
		cleanup.Error = err.Error()
		if result.Failure == nil {
			setFailure(result, PhaseCleanup, classifyDetachedError(cleanupContext, "environment_cleanup_failed", err))
		}
	}
	result.Cleanup = cleanup
}

func detachedTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), timeout)
}

func classifyError(parent, operationContext context.Context, defaultCode string, err error) *Failure {
	if failure := contextFailure(parent, operationContext); failure != nil {
		return failure
	}
	var classified *classifiedError
	if errors.As(err, &classified) {
		failure := classified.failure
		return &failure
	}
	return NewFailure(ClassificationInfrastructureFailure, defaultCode, err.Error())
}

func classifyDetachedError(operationContext context.Context, defaultCode string, err error) *Failure {
	if errors.Is(operationContext.Err(), context.DeadlineExceeded) {
		return NewFailure(ClassificationInfrastructureFailure, defaultCode+"_timeout", operationContext.Err().Error())
	}
	var classified *classifiedError
	if errors.As(err, &classified) {
		failure := classified.failure
		return &failure
	}
	return NewFailure(ClassificationInfrastructureFailure, defaultCode, err.Error())
}

func contextFailure(parent, operationContext context.Context) *Failure {
	if errors.Is(parent.Err(), context.Canceled) {
		return NewFailure(ClassificationCancelled, "job_cancelled", parent.Err().Error())
	}
	if errors.Is(operationContext.Err(), context.DeadlineExceeded) {
		return NewFailure(ClassificationTimedOut, "job_timeout", operationContext.Err().Error())
	}
	if errors.Is(operationContext.Err(), context.Canceled) {
		return NewFailure(ClassificationCancelled, "job_cancelled", operationContext.Err().Error())
	}
	return nil
}

func setFailure(result *Result, phase Phase, failure *Failure) {
	if result.Failure != nil || failure == nil {
		return
	}
	result.Status = "failed"
	result.Classification = failure.Classification
	result.Phase = phase
	result.Failure = failure
}

func finishResult(result Result) Result {
	result.CompletedAt = time.Now().UTC()
	result.Usage.WallTimeMilliseconds = result.CompletedAt.Sub(result.StartedAt).Milliseconds()
	if result.Failure == nil {
		result.Phase = PhaseCompleted
	}
	return result
}

func FailedResult(jobID string, phase Phase, classification Classification, code string, err error) Result {
	now := time.Now().UTC()
	return Result{
		SchemaVersion:  ResultSchemaVersion,
		JobID:          jobID,
		Status:         "failed",
		Classification: classification,
		Phase:          phase,
		Usage:          UsageResult{},
		Failure:        NewFailure(classification, code, err.Error()),
		StartedAt:      now,
		CompletedAt:    now,
	}
}
