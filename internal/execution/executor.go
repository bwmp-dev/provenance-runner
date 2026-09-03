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
	beforeExecute     func(context.Context, ExecutionStart) error
}

type ExecutorOptions struct {
	CollectionTimeout time.Duration
	CleanupTimeout    time.Duration
	BeforeExecute     func(context.Context, ExecutionStart) error
}

type ExecutionStart struct {
	JobID               string
	Provider            string
	EnvironmentIdentity string
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
		beforeExecute:     options.BeforeExecute,
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

	preparationContext, cancelPreparation := context.WithTimeout(parent, job.PreparationTimeout())
	defer cancelPreparation()

	result.Phase = PhaseResolution
	environment, err := provider.Resolve(preparationContext, Request{
		JobID:       job.ID,
		Environment: job.Environment,
		Limits:      Limits{MaxOutputBytes: job.OutputLimit()},
	})
	if err != nil {
		setFailure(&result, PhaseResolution, classifyError(parent, preparationContext, "provider_resolution_failed", err))
		return finishResult(result)
	}
	if failure := contextFailure(parent, preparationContext); failure != nil {
		setFailure(&result, PhaseResolution, failure)
		return finishResult(result)
	}
	if environment == nil {
		setFailure(&result, PhaseResolution, NewFailure(ClassificationInfrastructureFailure, "provider_returned_no_environment", "provider returned a nil environment"))
		return finishResult(result)
	}
	result.Environment = &EnvironmentResult{Provider: provider.Name(), Identity: environment.Identity()}
	if reporter, ok := environment.(ResourceClassReporter); ok {
		resourceClass := reporter.ResourceClass()
		result.Usage.ResourceClass = &resourceClass
	}

	result.Phase = PhasePreparation
	prepared, prepareErr := environment.Prepare(preparationContext)
	if prepareErr != nil {
		setFailure(&result, PhasePreparation, classifyError(parent, preparationContext, "environment_preparation_failed", prepareErr))
	}
	if prepared == nil {
		if prepareErr == nil {
			setFailure(&result, PhasePreparation, NewFailure(ClassificationInfrastructureFailure, "provider_returned_no_prepared_environment", "provider returned a nil prepared environment"))
		}
		return finishResult(result)
	}
	if observer := observerFromContext(parent); observer != nil {
		if attacher, ok := prepared.(ObserverAttacher); ok {
			attacher.AttachObserver(observer)
		}
	}

	if result.Failure == nil {
		if failure := contextFailure(parent, preparationContext); failure != nil {
			setFailure(&result, PhasePreparation, failure)
		} else {
			start := ExecutionStart{JobID: job.ID, Provider: provider.Name(), EnvironmentIdentity: result.Environment.Identity}
			if job.UsesPhaseTimeouts() {
				executionContext, cancelExecution := context.WithTimeout(parent, job.Timeout())
				executePrepared(parent, executionContext, prepared, start, e.beforeExecute, &result)
				cancelExecution()
			} else {
				executePrepared(parent, preparationContext, prepared, start, e.beforeExecute, &result)
			}
		}
	}

	collectPrepared(parent, prepared, e.collectionTimeout, &result)
	cleanupTimeout := e.cleanupTimeout
	if job.UsesPhaseTimeouts() {
		cleanupTimeout = job.GracefulShutdownTimeout()
	}
	cleanupPrepared(parent, prepared, cleanupTimeout, &result)
	return finishResult(result)
}

func executePrepared(parent, runContext context.Context, prepared PreparedEnvironment, start ExecutionStart, beforeExecute func(context.Context, ExecutionStart) error, result *Result) {
	result.Phase = PhaseExecution
	if beforeExecute != nil {
		if err := beforeExecute(runContext, start); err != nil {
			setFailure(result, PhaseExecution, classifyError(parent, runContext, "before_execute_failed", err))
			return
		}
		if failure := contextFailure(parent, runContext); failure != nil {
			setFailure(result, PhaseExecution, failure)
			return
		}
	}
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
	result.Usage.CompleteLogState = output.EvidenceUsage.CompleteLogState
	result.Usage.CompleteLogTruncated = output.EvidenceUsage.CompleteLogTruncated
	result.Usage.StructuredEventsTruncated = output.EvidenceUsage.EventsTruncated
	result.Usage.EventChannelMaximumBytes = output.EvidenceUsage.EventChannelMaximumBytes
	result.Usage.EventChannelBufferedBytes = output.EvidenceUsage.EventChannelBufferedBytes
	result.Usage.EventChannelResourceBytes = output.EvidenceUsage.EventChannelResourceBytes
	result.Usage.EventChannelOverflowed = output.EvidenceUsage.EventChannelOverflowed
	result.Usage.EventChannelRemoved = output.EvidenceUsage.EventChannelRemoved
	if output.ResourceUsage != nil {
		usage := *output.ResourceUsage
		result.Usage.MeasuredResources = &usage
	}
	if err != nil {
		result.Logs.Error = err.Error()
		if result.Failure == nil {
			setFailure(result, PhaseCollection, classifyDetachedError(collectionContext, "output_collection_failed", err))
		}
	}
}

type observerContextKey struct{}

func WithObserver(ctx context.Context, observer ExecutionObserver) context.Context {
	if observer == nil {
		return ctx
	}
	return context.WithValue(ctx, observerContextKey{}, observer)
}

func observerFromContext(ctx context.Context) ExecutionObserver {
	observer, _ := ctx.Value(observerContextKey{}).(ExecutionObserver)
	return observer
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
