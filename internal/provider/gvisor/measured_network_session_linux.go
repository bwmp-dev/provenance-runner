//go:build linux

package gvisor

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sync"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

var errMeasuredSession = errors.New("measured_network_session_unavailable")

// This is trusted in-process controller configuration, not a worker RPC.
// The bundle must already be prepared and the authority freshly reconciled.
// Journals, measurement, tools and standard files remain borrowed.
type measuredSessionConfig struct {
	Launch              MeasuredNetworkLaunchConfig
	RouterMapping       np.MappedIdentity
	Uplinks             *np.HostUplinkJournal
	Tools               np.RouteTools
	Boundary            *measuredLocalBoundary
	ControllerResources *np.ControllerResources
	Resolver            np.Exchange
}

// measuredNetworkSession coordinates the complete per-job network lifetime.
// It owns job DNS, but not global reservations or the measured root mount.
type measuredNetworkSession struct {
	mu               sync.Mutex
	process          *MeasuredNetworkProcess
	router           *RouterOwner
	link             *np.PrivateJobLink
	uplink           *np.HostUplink
	native           *np.RetainedRoute
	authority        *np.AuthorityRoute
	bundle           *measuredBundle
	done             chan struct{}
	dnsDone          chan struct{}
	dnsRefreshDone   chan struct{}
	dnsRefreshCancel context.CancelFunc
	dns              *measuredSessionDNS
	budget           *measuredSessionBudget
	reason           error
	outcomeSet       bool
	stopping, closed bool
}

// A non-nil result owns the bundle, authority and every created component,
// including on partial failure. Cleanup must succeed before capacity reuse.
func startMeasuredSession(ctx context.Context, c measuredSessionConfig) (*measuredNetworkSession, error) {
	return startMeasuredSessionWithBudget(ctx, c, nil)
}

func startMeasuredSessionWithBudget(ctx context.Context, c measuredSessionConfig, budget *measuredSessionBudget) (*measuredNetworkSession, error) {
	groups, err := os.Getgroups()
	l := c.Launch
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || err != nil || len(groups) != 0 || l.Job == nil || l.Bundle == nil || l.Bundle.owner == nil || l.Scope != l.Bundle.scope || l.Journal != l.Bundle.owner.cgroups || l.Authority == nil || l.Measurement == nil || c.Uplinks == nil || !validPreparationMapping(l.Mapping) || !validPreparationMapping(c.RouterMapping) {
		return nil, errMeasuredSession
	}
	l.Job = proto.Clone(l.Job).(*p.JobSpecification)
	if c.Boundary.check(l.Job, l.Mapping, c.RouterMapping) != nil {
		return nil, errMeasuredSession
	}
	// No router/workload mapped identity may overlap within either namespace.
	for _, a := range []uint32{l.Mapping.UID, l.Mapping.OverflowUID} {
		if a == c.RouterMapping.UID || a == c.RouterMapping.OverflowUID {
			return nil, errMeasuredSession
		}
	}
	for _, a := range []uint32{l.Mapping.GID, l.Mapping.OverflowGID} {
		if a == c.RouterMapping.GID || a == c.RouterMapping.OverflowGID {
			return nil, errMeasuredSession
		}
	}
	if l.Bundle.owner.check(l.Bundle, l.Job) != nil || l.Bundle.checkPrepared(l.Mapping) != nil || l.Authority.CheckJob(l.Job) != nil {
		return nil, errMeasuredSession
	}
	if budget == nil {
		budget, err = newMeasuredSessionBudget(ctx, l.Job.EffectivePolicy.PreparationTimeout.AsDuration(), l.Job.EffectivePolicy.ExecutionTimeout.AsDuration())
		if err != nil {
			return nil, err
		}
	}
	if budget.claim(l.Job.EffectivePolicy.PreparationTimeout.AsDuration(), l.Job.EffectivePolicy.ExecutionTimeout.AsDuration()) != nil {
		budget.close()
		return nil, errMeasuredSession
	}
	ctx = budget.ctx
	s := &measuredNetworkSession{authority: l.Authority, bundle: l.Bundle, done: make(chan struct{}), budget: budget}
	fail := func(err error) (*measuredNetworkSession, error) {
		s.reason, s.outcomeSet = errors.Join(errMeasuredSession, err, context.Cause(ctx)), true
		return s, errors.Join(s.reason, s.Close(context.Background()))
	}
	s.dns, err = newMeasuredSessionDNS(l.Job, c.Boundary.dns, c.Resolver)
	if err != nil {
		return fail(err)
	}
	bindings, err := s.dns.resolve(ctx)
	if err != nil {
		return fail(err)
	}
	s.router, err = startRouterOwnerWithResources(ctx, l.Job, l.Journal, l.Measurement, c.RouterMapping, c.ControllerResources)
	if err != nil {
		return fail(err)
	}
	s.process, err = StartMeasuredNetworkProcess(ctx, l)
	if err != nil {
		return fail(err)
	}
	s.link, err = np.CreatePrivateJobLink(ctx, l.Job.GetLease().GetJobId(), s.router.Child(), s.process.Child(), c.Tools)
	if err != nil {
		return fail(err)
	}
	s.uplink, err = c.Uplinks.Create(ctx, l.Job, s.link)
	if err != nil {
		return fail(err)
	}
	s.native, err = np.NewRetainedRoute(l.Job.GetLease().GetJobId(), s.router.Child(), s.process.Child(), c.Tools)
	if err != nil {
		return fail(err)
	}
	if err = s.authority.Start(ctx, bindings, s.native); err != nil {
		return fail(err)
	}
	if err = s.authority.ObserveInstalledForUplink(ctx, l.Job, s.process.Child(), s.link, s.uplink); err != nil {
		return fail(err)
	}
	if s.router.dns.validate() != nil {
		return fail(ErrRouterOwner)
	}
	s.dnsDone = make(chan struct{})
	dns, authority := s.router.dns, s.authority
	go func() {
		defer close(s.dnsDone)
		_ = authority.ServeDNS(ctx, dns.udp, dns.tcp, []netip.Addr{netip.MustParseAddr("10.0.1.2")})
	}()
	refreshCtx, refreshCancel := context.WithCancel(ctx)
	s.dnsRefreshCancel = refreshCancel
	s.dnsRefreshDone = make(chan struct{})
	refreshDone, resolver := s.dnsRefreshDone, s.dns
	go func() {
		defer close(refreshDone)
		resolver.renew(refreshCtx, authority, bindings)
	}()
	routerDone, authorityDone, processDone := s.router.Done(), s.authority.Done(), s.process.done
	go func() {
		var reason error
		select {
		case <-ctx.Done():
			reason = context.Cause(ctx)
		case <-routerDone:
			reason = ErrRouterOwner
		case <-authorityDone:
			reason = np.ErrAuthorityWithdrawn
		case <-processDone:
			reason = s.process.exitErr
			// An already lost dependency must not become a successful job just
			// because the process-exit channel won the select race.
			select {
			case <-routerDone:
				reason = ErrRouterOwner
			default:
			}
			select {
			case <-authorityDone:
				reason = np.ErrAuthorityWithdrawn
			default:
			}
			if ctx.Err() != nil {
				reason = context.Cause(ctx)
			}
		case <-s.done:
			return
		}
		if cause := context.Cause(ctx); cause != nil {
			reason = cause
		}
		s.mu.Lock()
		if !s.stopping {
			s.reason = reason
			s.outcomeSet = true
		}
		s.mu.Unlock()
		_ = s.Close(context.Background())
	}()
	return s, nil
}

func (s *measuredNetworkSession) Release(ctx context.Context) error {
	if s == nil {
		return errMeasuredSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping || s.closed || s.process == nil || s.router == nil {
		return errMeasuredSession
	}
	if s.router.dns.validate() != nil {
		return errMeasuredSession
	}
	select {
	case <-s.router.Done():
		return errMeasuredSession
	default:
	}
	if ctx == nil || ctx.Err() != nil || s.budget.beginExecution() != nil {
		if s.budget != nil {
			s.budget.cancel(errMeasuredSession)
		}
		return errMeasuredSession
	}
	release, cancel := context.WithCancel(s.budget.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := s.process.Release(release, s.link, s.uplink); err != nil {
		s.budget.cancel(err)
		return err
	}
	return nil
}

func (s *measuredNetworkSession) ObserveRuntime(ctx context.Context) (*runtimeidentity.NetworkObservation, error) {
	if s == nil {
		return nil, errMeasuredSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping || s.closed || !s.budget.active() || s.process == nil || s.router == nil || s.router.dns.validate() != nil {
		return nil, errMeasuredSession
	}
	return s.process.ObserveRuntime(ctx)
}

// Close continues independent process cleanup even if firewall cleanup fails.
// It retains the objects needed to retry; done closes only after all owned
// process, route, link, uplink and bundle retirement succeeds.
func (s *measuredNetworkSession) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return errMeasuredSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.stopping = true
	if !s.outcomeSet {
		s.reason, s.outcomeSet = context.Canceled, true
	}
	s.budget.close()
	var result error
	if s.dnsRefreshCancel != nil {
		s.dnsRefreshCancel()
	}
	if s.authority != nil {
		if err := s.authority.Close(); err != nil {
			result = errors.Join(result, err)
		} else {
			s.authority = nil
		}
	}
	if s.dnsDone != nil {
		if s.router != nil {
			result = errors.Join(result, s.router.dns.Close())
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-s.dnsDone:
			s.dnsDone = nil
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
		case <-timer.C:
			result = errors.Join(result, errMeasuredSession)
		}
		timer.Stop()
	}
	if s.dnsRefreshDone != nil {
		timer := time.NewTimer(6 * time.Second)
		select {
		case <-s.dnsRefreshDone:
			s.dnsRefreshDone = nil
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
		case <-timer.C:
			result = errors.Join(result, errMeasuredSession)
		}
		timer.Stop()
	}
	processClean := s.process == nil
	if s.process != nil {
		err := s.process.Close(ctx)
		processClean = err == nil
		result = errors.Join(result, err)
	}
	if s.uplink != nil {
		if err := s.uplink.Close(ctx); err != nil {
			result = errors.Join(result, err)
		} else {
			s.uplink = nil
		}
	}
	// Native firewall cleanup needs job0 to remain present until disconnected.
	if s.authority == nil && s.link != nil {
		if err := s.link.Close(ctx); err != nil {
			result = errors.Join(result, err)
		} else {
			s.link = nil
		}
	}
	if s.authority == nil && s.native != nil {
		if err := s.native.Close(); err != nil {
			result = errors.Join(result, err)
		} else {
			s.native = nil
		}
	}
	routerClean := s.router == nil
	if s.router != nil {
		err := s.router.Close(ctx)
		routerClean = err == nil
		result = errors.Join(result, err)
	}
	if processClean && routerClean && s.bundle != nil {
		if err := s.bundle.owner.cleanup(ctx, s.bundle); err != nil {
			result = errors.Join(result, err)
		} else {
			s.bundle = nil
		}
	}
	if result == nil {
		s.closed = true
		if s.done != nil {
			close(s.done)
		}
	}
	return result
}

func (s *measuredNetworkSession) Wait(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errMeasuredSession
	}
	select {
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.reason
	case <-ctx.Done():
		return errors.Join(ctx.Err(), s.Close(context.Background()))
	}
}
