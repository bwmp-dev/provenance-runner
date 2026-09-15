//go:build linux

package measuredclient

import (
	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

// SessionFailure remains an infrastructure failure, even when root has proved
// retirement. It exposes no successful outcome or publishable observation.
// Zero values and decoded JSON carry no retirement authority.
type SessionFailure struct {
	observation *runtimeidentity.NetworkObservation
	completion  *cc.RootCompletion
}

func (*SessionFailure) Error() string { return "measured_worker_session_failed" }
func (*SessionFailure) Unwrap() error { return ErrSession }

// RetiredFor verifies historical cleanup for this exact execution, not merely
// a matching lease or a guest claim. False means capacity must remain held until
// the caller obtains independent authenticated cleanup evidence.
func (f *SessionFailure) RetiredFor(job *p.JobSpecification) bool {
	if f == nil || f.observation == nil || f.completion == nil || job == nil {
		return false
	}
	if _, _, err := f.completion.Outcome(); err != nil {
		return false
	}
	hash, err := runtimeidentity.ExecutionJobSHA256(job)
	if err != nil {
		return false
	}
	_, err = f.observation.SnapshotForExecution(hash, job.Lease, job.Attempt, job.Hashes)
	return err == nil
}
