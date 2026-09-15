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
	return s.observeInstalled(ctx, job, nil, false, nil, false, nil, false)
}

// ObserveInstalledForChild additionally binds the observation to the exact
// retained workload owner used to construct this route. A matching job label,
// PID, mapping, or separately retained namespace is not a substitute. Failure
// permanently withdraws this authority, including a nil or foreign owner.
// This Linux-only launch check does not grant cleanup or resource authority.
func (s *AuthorityRoute) ObserveInstalledForChild(ctx context.Context, job *p.JobSpecification, child *ChildNamespaces) error {
	return s.observeInstalled(ctx, job, child, true, nil, false, nil, false)
}

// ObserveInstalledForLink also verifies the actual owned veth pair belongs to
// this native route's exact router and workload, not merely matching labels.
func (s *AuthorityRoute) ObserveInstalledForLink(ctx context.Context, job *p.JobSpecification, child *ChildNamespaces, link *PrivateJobLink) error {
	return s.observeInstalled(ctx, job, child, true, link, true, nil, false)
}

// ObserveInstalledForUplink additionally requires the exact journaled host
// uplink, its private-link owner, and the actual fixed router/host layout.
func (s *AuthorityRoute) ObserveInstalledForUplink(ctx context.Context, job *p.JobSpecification, child *ChildNamespaces, link *PrivateJobLink, uplink *HostUplink) error {
	return s.observeInstalled(ctx, job, child, true, link, true, uplink, true)
}

func (s *AuthorityRoute) observeInstalled(ctx context.Context, job *p.JobSpecification, child *ChildNamespaces, requireChild bool, link *PrivateJobLink, requireLink bool, uplink *HostUplink, requireUplink bool) error {
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
	if requireLink && (link == nil || link.carrier == nil || link.carrier.router != native.router || link.carrier.workload != native.workload || link.Validate(ctx) != nil) {
		return s.withdrawLocked(ErrNamespace)
	}
	if requireUplink && (!requireLink || uplink == nil || uplink.private != link || uplink.pair == nil || uplink.pair.carrier.router != native.router || uplink.pair.carrier.workload != native.workload || !uplink.matchesJob(job) || uplink.Validate(ctx) != nil) {
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
		if requireLink && link.Validate(ctx) != nil {
			return ErrNamespace
		}
		if requireUplink && uplink.Validate(ctx) != nil {
			return ErrNamespace
		}
		return nil
	}()
	s.route.mu.Unlock()
	if err != nil {
		return s.withdrawLocked(err)
	}
	return nil
}
