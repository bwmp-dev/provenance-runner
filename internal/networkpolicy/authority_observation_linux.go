//go:build linux

package networkpolicy

import (
	"context"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

// ObserveInstalled requires this attempt's real retained kernel actuator, not
// an arbitrary OwnedRoute implementation or requested network-mode label.
// Failure withdraws the owning route. This is an installation/authority check,
// not proof of a measured rootfs, a Sentry launch, or completed cleanup.
func (s *AuthorityRoute) ObserveInstalled(ctx context.Context, job *p.JobSpecification) error {
	return s.observeInstalled(ctx, job, nil, false)
}

// ObserveInstalledForChild additionally binds the observation to the exact
// retained workload owner used to construct this route. A matching job label,
// PID, mapping, or separately retained namespace is not a substitute. Failure
// permanently withdraws this authority, including a nil or foreign owner.
// This Linux-only launch check does not grant cleanup or resource authority.
func (s *AuthorityRoute) ObserveInstalledForChild(ctx context.Context, job *p.JobSpecification, child *ChildNamespaces) error {
	return s.observeInstalled(ctx, job, child, true)
}

func (s *AuthorityRoute) observeInstalled(ctx context.Context, job *p.JobSpecification, child *ChildNamespaces, requireChild bool) error {
	if err := s.CheckJob(job); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.withdrawn || s.route == nil || ctx == nil || ctx.Err() != nil {
		return s.withdrawLocked(ErrAuthority)
	}
	native, ok := s.route.route.(*RetainedRoute)
	if !ok {
		return s.withdrawLocked(ErrNamespace)
	}
	// Serialize readback with DNS refresh/expiry. No independent route caller
	// can observe a half-renewed firewall as the current installed snapshot.
	s.route.mu.Lock()
	err := func() error {
		if s.route.withdrawn || s.route.ctx.Err() != nil || !time.Now().Before(s.route.rules.ExpiresAt()) {
			return ErrExpired
		}
		if err := native.observeInstalled(ctx, s.authority.lease.JobId, child, requireChild); err != nil {
			return err
		}
		if _, err := s.authority.Deadline(time.Now()); err != nil {
			return err
		}
		if !time.Now().Before(s.route.rules.ExpiresAt()) {
			return ErrExpired
		}
		return nil
	}()
	s.route.mu.Unlock()
	if err != nil {
		return s.withdrawLocked(err)
	}
	return nil
}
