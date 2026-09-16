//go:build linux

package execution

import (
	"context"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

// AcquireMeasuredTestSecretFiles requires a sealed exact-job root observation
// as well as current authority before invoking the trusted gateway callback.
// It neither impersonates a legacy sandbox nor accepts an observation from JSON.
// The caller owns successful files until root/gofer retirement.
func AcquireMeasuredTestSecretFiles(ctx context.Context, job *p.JobSpecification, observed *runtimeidentity.NetworkObservation) (*ts.Files, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || job == nil || len(job.TestSecrets) == 0 || ts.ValidateSelection(job) != nil {
		return nil, time.Time{}, ts.ErrUnavailable
	}
	hash, err := runtimeidentity.ExecutionJobSHA256(job)
	if err != nil {
		return nil, time.Time{}, ts.ErrUnavailable
	}
	if _, err := observed.SnapshotForExecution(hash, job.Lease, job.Attempt, job.Hashes); err != nil {
		return nil, time.Time{}, ts.ErrUnavailable
	}
	guard := NetworkAuthorityRoute(ctx)
	if guard == nil || guard.CheckJob(job) != nil {
		return nil, time.Time{}, ts.ErrUnavailable
	}
	source, _ := ctx.Value(testSecretSourceKey{}).(TestSecretSource)
	if source == nil {
		return nil, time.Time{}, ts.ErrUnavailable
	}
	files, expires, err := source(ctx)
	ceiling, authorityErr := guard.CurrentLeaseExpiry(job)
	if err != nil || files == nil || ctx.Err() != nil || authorityErr != nil || !expires.After(time.Now()) || expires.After(ceiling) {
		if files != nil {
			files.Close()
		}
		return nil, time.Time{}, ts.ErrUnavailable
	}
	return files, expires, nil
}
