//go:build linux

package gvisor

import (
	"context"
	"crypto/sha256"
	"sync/atomic"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

// The same binder survives every renewal, preserving each hostname's original
// address pin and permanent rebinding refusals. Local maximum, resolver and
// sensitive destinations are trusted controller configuration, never job input.
type measuredSessionDNS struct {
	binder    *np.Binder
	hosts     []string
	refreshes atomic.Uint64
}

func newMeasuredSessionDNS(job *p.JobSpecification, local np.LocalV2Boundary, resolver np.Exchange) (*measuredSessionDNS, error) {
	if job == nil || job.Lease == nil || job.EffectivePolicy == nil || job.EffectivePolicy.NetworkV2 == nil || job.EffectivePolicy.NetworkV2.Mode == p.NetworkMode_NETWORK_MODE_NONE {
		return nil, np.ErrDNS
	}
	if _, err := np.NewAuthority(job); err != nil {
		return nil, err
	}
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(job.EffectivePolicy)
	if err != nil {
		return nil, np.ErrDNS
	}
	binder, err := np.NewV2Binder(job.Lease.JobId, raw, sha256.Sum256(raw), local, resolver)
	if err != nil {
		return nil, err
	}
	s := &measuredSessionDNS{binder: binder}
	for _, permission := range job.EffectivePolicy.NetworkV2.Permissions {
		// Released canonical tuples are already sorted by hostname.
		if len(s.hosts) == 0 || s.hosts[len(s.hosts)-1] != permission.Hostname {
			s.hosts = append(s.hosts, permission.Hostname)
		}
	}
	return s, nil
}

func (s *measuredSessionDNS) resolve(ctx context.Context) ([]np.Binding, error) {
	if s == nil || s.binder == nil || ctx == nil || ctx.Err() != nil || len(s.hosts) == 0 {
		return nil, np.ErrDNS
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	bindings := make([]np.Binding, 0, len(s.hosts))
	for _, host := range s.hosts {
		binding, err := s.binder.Resolve(ctx, host)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	if ctx.Err() != nil {
		return nil, np.ErrDNS
	}
	return bindings, nil
}

func sessionDNSRefreshDelay(bindings []np.Binding, now time.Time) (time.Duration, error) {
	if len(bindings) == 0 || now.IsZero() {
		return 0, np.ErrDNS
	}
	deadline := bindings[0].ExpiresAt().Truncate(time.Second)
	for _, binding := range bindings {
		if !binding.ValidAt(now) {
			return 0, np.ErrExpired
		}
		if expiry := binding.ExpiresAt().Truncate(time.Second); expiry.Before(deadline) {
			deadline = expiry
		}
	}
	delay := deadline.Sub(now) / 2
	if delay <= 0 {
		return 0, np.ErrExpired
	}
	return delay, nil
}

func (s *measuredSessionDNS) renew(ctx context.Context, authority *np.AuthorityRoute, bindings []np.Binding) {
	for {
		delay, err := sessionDNSRefreshDelay(bindings, time.Now())
		if err != nil {
			_ = authority.Withdraw()
			return
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-authority.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		bindings, err = s.resolve(ctx)
		if err != nil || authority.RefreshDNS(ctx, bindings) != nil {
			_ = authority.Withdraw()
			return
		}
		s.refreshes.Add(1)
	}
}
