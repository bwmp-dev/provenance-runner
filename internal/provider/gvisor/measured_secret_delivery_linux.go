//go:build linux

package gvisor

import (
	"context"
	"time"

	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
)

func (c *measuredController) SupportsTestSecretStorage() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ready && !c.closed && !c.stopping && c.config.Bundles != nil && c.config.Bundles.secretParentValid()
}

// MaterializeTestSecrets is a trusted root-service operation after observation,
// before Java bootstrap. It binds names to the original admitted selection and
// refuses delivery beyond the currently acknowledged lease ceiling. It never
// accepts a path, identity, renewed timestamp or value-bearing JSON payload.
func (j *measuredControllerJob) MaterializeTestSecrets(ctx context.Context, descriptors []ts.Descriptor, expires time.Time) error {
	if j == nil || j.controller == nil || ctx == nil || ctx.Err() != nil {
		return errMeasuredSession
	}
	c := j.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if j.retired || c.active != j || c.stopping || !j.observed || j.session == nil || j.authority == nil || j.bundle == nil || !c.resourcesReady() || !j.budget.active() {
		return errMeasuredSession
	}
	refuse := func() error { j.budget.cancel(errMeasuredSession); return errMeasuredSession }
	if ts.ValidateSelection(j.job) != nil || len(j.job.TestSecrets) == 0 || len(j.job.TestSecrets) != len(descriptors) {
		return refuse()
	}
	for i, ref := range j.job.TestSecrets {
		if descriptors[i].Name != ref.Name {
			return refuse()
		}
	}
	ceiling, err := j.authority.CurrentLeaseExpiry(j.job)
	if err != nil || !expires.After(time.Now()) || expires.After(ceiling) {
		return refuse()
	}
	if j.bundle.stageSecrets(ctx, j.job, descriptors, expires) != nil {
		return refuse()
	}
	return nil
}
