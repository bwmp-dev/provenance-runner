package execution

import (
	"context"
	"errors"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

var ErrNetworkAuthorityLost = errors.New("network_authority_lost")

type networkAuthorityKey struct{}

// NetworkAuthorityRoute returns only the trusted supervisor injected by
// SuperviseNetworkAuthority. It cannot be selected through job/environment JSON.
// The sandbox still must install its owned route and prove its runtime identity.
func NetworkAuthorityRoute(ctx context.Context) *networkpolicy.AuthorityRoute {
	value, _ := ctx.Value(networkAuthorityKey{}).(*networkpolicy.AuthorityRoute)
	return value
}

// SuperviseNetworkAuthority owns the guard through the worker's entire cleanup.
// It refuses invocation without fresh authority for the exact job. Loss cancels
// the worker independently of gateway polling, then waits for its normal result
// and cleanup. Route teardown failure cannot be reclassified as cancellation or
// successful capacity release. Callers must retain/drain failed cleanup as usual.
func SuperviseNetworkAuthority(ctx context.Context, job *p.JobSpecification, guard *networkpolicy.AuthorityRoute, execute func(context.Context) Result) Result {
	now := time.Now().UTC()
	early := func() Result {
		return Result{Status: "failed", Classification: ClassificationInfrastructureFailure, Phase: PhasePreparation, StartedAt: now, CompletedAt: time.Now().UTC(), Failure: NewFailure(ClassificationInfrastructureFailure, "network_authority_lost", "network authority unavailable before execution")}
	}
	if ctx == nil || ctx.Err() != nil || execute == nil || guard == nil {
		result := early()
		if guard != nil {
			applyNetworkCleanup(&result, guard.Close())
		}
		return result
	}
	if err := guard.CheckJob(job); err != nil {
		result := early()
		applyNetworkCleanup(&result, guard.Close())
		return result
	}
	worker, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)
	worker = context.WithValue(worker, networkAuthorityKey{}, guard)
	finished, watched := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watched)
		select {
		case <-guard.Done():
			cancel(ErrNetworkAuthorityLost)
		case <-finished:
		}
	}()
	result := execute(worker)
	close(finished)
	<-watched
	// Stop the monitor before our own successful teardown withdraws the route.
	// A completed worker is not turned into a failure by that teardown itself.
	lost := errors.Is(context.Cause(worker), ErrNetworkAuthorityLost)
	select {
	case <-guard.Done():
		lost = true
	default:
	}
	if lost && (result.Cleanup == nil || result.Cleanup.Succeeded) {
		result.Status = "failed"
		result.Classification = ClassificationInfrastructureFailure
		result.Failure = NewFailure(ClassificationInfrastructureFailure, "network_authority_lost", "execution stopped after network authority loss")
	}
	applyNetworkCleanup(&result, guard.Close())
	return result
}

func applyNetworkCleanup(result *Result, err error) {
	if err == nil {
		return
	}
	result.Status = "failed"
	result.Classification = ClassificationInfrastructureFailure
	result.Phase = PhaseCleanup
	result.Failure = NewFailure(ClassificationInfrastructureFailure, "network_cleanup_failed", "owned network teardown could not be proven")
	result.Cleanup = &CleanupResult{Attempted: true, Succeeded: false, Error: "owned network teardown could not be proven"}
}
