//go:build linux

package gvisor

import (
	"context"
	"net/netip"
	"os"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

// These are trusted in-process provisioning/ownership types, NOT wire schemas.
// Never decode worker payloads into them. A provider-specific root admission
// function must derive commands and input identities from verified metadata.
// No path, UID mapping, local maximum or tool can be selected by a local request.
type MeasuredController = measuredController
type MeasuredControllerConfig = measuredControllerConfig
type MeasuredControllerJob = measuredControllerJob
type MeasuredBundleJournal = measuredBundleJournal
type MeasuredLocalBoundary = measuredLocalBoundary
type MeasuredGuestCommand = measuredGuestCommand
type MeasuredInput = measuredInput

func OpenMeasuredBundleJournal(parent, state *os.File, cgroups *np.JobCgroupJournal) (*MeasuredBundleJournal, error) {
	return openMeasuredBundleJournal(parent, state, cgroups)
}
func (j *measuredBundleJournal) Close() error { return j.close() }
func NewMeasuredLocalBoundary(maximum *p.EffectivePolicy, workload, router np.MappedIdentity, sensitive []netip.Prefix, ttl time.Duration) (*MeasuredLocalBoundary, error) {
	return newMeasuredLocalBoundary(maximum, workload, router, sensitive, ttl)
}

// OpenMeasuredController returns a non-nil owner even on a partial startup
// failure. Its caller must retry Close until it succeeds before closing journals
// or reusing capacity. The same rule applies to a non-nil Start result.
func OpenMeasuredController(ctx context.Context, config MeasuredControllerConfig) (*MeasuredController, error) {
	return newMeasuredController(ctx, config)
}
func (c *measuredController) Start(ctx context.Context, job *p.JobSpecification, command MeasuredGuestCommand, inputs []MeasuredInput, authority *np.AuthorityRoute, stdin, stdout, stderr *os.File) (*MeasuredControllerJob, error) {
	return c.start(ctx, job, command, inputs, authority, stdin, stdout, stderr)
}
func (j *measuredControllerJob) CompletedProcessExit() (int, error) { return j.completedProcessExit() }

// CompletedProcessOutcome separates actual process exit from infrastructure
// loss, only after retirement. Provider-reserved exits (Paper helper 125) and
// malformed guest output still require provider-specific failure handling.
func (j *measuredControllerJob) CompletedProcessOutcome() (int, bool, error) {
	return j.completedProcessOutcome()
}
