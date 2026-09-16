package execution

import (
	"context"
	"errors"
	"time"
)

// ExecuteOwned runs a trusted, already constructed provider session without
// converting its admission contract into a legacy local job. The session owns
// preparation and execution deadlines and any authenticated release callback.
// Collection and cleanup always run, including after cancellation or failure.
// This function does not admit jobs or manufacture runtime observations.
func ExecuteOwned(ctx context.Context, start ExecutionStart, prepared PreparedEnvironment) Result {
	if ctx == nil || prepared == nil {
		return FailedResult(start.JobID, PhasePreparation, ClassificationInfrastructureFailure, "owned_session_missing", errors.New("owned session is unavailable"))
	}
	result := Result{
		SchemaVersion: ResultSchemaVersion, JobID: start.JobID,
		Status: "passed", Classification: ClassificationPassed,
		Phase: PhasePreparation, StartedAt: time.Now().UTC(),
		Environment: &EnvironmentResult{Provider: start.Provider, Identity: start.EnvironmentIdentity},
	}
	if observer := observerFromContext(ctx); observer != nil {
		if attacher, ok := prepared.(ObserverAttacher); ok {
			attacher.AttachObserver(observer)
		}
	}
	if failure := contextFailure(ctx, ctx); failure != nil {
		setFailure(&result, PhasePreparation, failure)
	} else {
		executePrepared(ctx, ctx, prepared, start, nil, &result)
	}
	collectPrepared(ctx, prepared, defaultCollectionTimeout, &result)
	cleanupPrepared(ctx, prepared, 15*time.Second, &result)
	return finishResult(result)
}
