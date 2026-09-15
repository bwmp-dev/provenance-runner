package networkpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

// AuthorityRoute owns one attempt's authority and route together. Neither is
// exposed for independent renewal. Done signals permanent withdrawal, NOT
// successful cleanup or permission to release capacity. Close must succeed too.
type AuthorityRoute struct {
	mu                  sync.Mutex
	authority           *Authority
	route               *RouteSession
	bindings            []Binding
	installed           time.Time
	ctx                 context.Context
	stop                context.CancelFunc
	wake, done, watched chan struct{}
	withdrawn           bool
	cleanupErr          error
	controlUpdates      []authorityControlUpdate
	controlSequence     uint64
	controlChanged      chan struct{}
	controlChecked      time.Time
	controlUnavailable  bool
}

// ErrAuthorityWithdrawn reports a valid observation for an irreversibly stopped
// attempt. Cleanup acknowledgements may still proceed; this is not permission.
var ErrAuthorityWithdrawn = errors.New("network_authority_withdrawn")

// NewAuthorityRoute grants nothing and installs nothing. The stream owner must
// supply a fresh authenticated reconciliation before Start can install a route.
func NewAuthorityRoute(ctx context.Context, job *p.JobSpecification) (*AuthorityRoute, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrAuthority
	}
	a, err := NewAuthority(job)
	if err != nil {
		return nil, err
	}
	if a.policy.Mode == p.NetworkMode_NETWORK_MODE_NONE {
		return nil, ErrAuthority
	}
	ctx, stop := context.WithCancel(ctx)
	s := &AuthorityRoute{authority: a, ctx: ctx, stop: stop, wake: make(chan struct{}, 1), done: make(chan struct{}), watched: make(chan struct{}), controlChanged: make(chan struct{})}
	go s.watch()
	return s, nil
}

func (s *AuthorityRoute) Done() <-chan struct{} { return s.done }

// CheckJob checks the immutable owner and current deadline without installing
// protection. The provider must still Start the route before exposing a job.
func (s *AuthorityRoute) CheckJob(job *p.JobSpecification) error {
	if s == nil {
		return ErrAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	other, err := NewAuthority(job)
	if err != nil || s.withdrawn || s.ctx.Err() != nil {
		return s.withdrawLocked(ErrAuthority)
	}
	if other.digest != s.authority.digest || other.lease.JobId != s.authority.lease.JobId || other.lease.LeaseId != s.authority.lease.LeaseId || other.lease.ExecutionId != s.authority.lease.ExecutionId || !proto.Equal(other.attempt, s.authority.attempt) {
		return s.withdrawLocked(ErrAuthority)
	}
	if _, err := s.authority.Deadline(time.Now()); err != nil {
		return s.withdrawLocked(err)
	}
	if s.route != nil {
		if _, err := s.route.DNS(); err != nil {
			return s.withdrawLocked(err)
		}
	}
	return nil
}

func (s *AuthorityRoute) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *AuthorityRoute) withdrawLocked(reason error) error {
	if !s.withdrawn {
		s.withdrawn = true
		s.controlUpdates = nil
		s.authority.Withdraw()
		close(s.done)
		s.stop()
	}
	if s.route != nil {
		s.cleanupErr = errors.Join(s.cleanupErr, s.route.Withdraw())
	}
	return errors.Join(reason, s.cleanupErr)
}

// Reconcile serializes the current authenticated observation with installed
// enforcement. Reduced deadlines apply atomically before returning success.
func (s *AuthorityRoute) Reconcile(ctx context.Context, value *p.LeaseReconciliation, features []p.ProtocolFeature, credentialExpiry time.Time) error {
	if s == nil {
		return ErrAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.withdrawn {
		if err := s.authority.Reconcile(value, features, credentialExpiry, time.Now()); err != nil {
			return errors.Join(err, s.cleanupErr)
		}
		return errors.Join(ErrAuthorityWithdrawn, s.cleanupErr)
	}
	if ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil {
		return s.withdrawLocked(ErrAuthority)
	}
	now := time.Now()
	if err := s.authority.Reconcile(value, features, credentialExpiry, now); err != nil {
		return s.withdrawLocked(err)
	}
	if _, err := s.authority.Deadline(now); err != nil {
		return s.withdrawLocked(ErrAuthorityWithdrawn)
	}
	if s.route != nil {
		if err := s.refreshLocked(ctx, s.bindings, false); err != nil {
			return err
		}
	}
	s.recordControlUpdateLocked(value, features, credentialExpiry)
	s.signal()
	return nil
}

// Start takes ownership even when installation fails: retain this supervisor
// and retry Close until cleanup succeeds. No route may be exposed beforehand.
func (s *AuthorityRoute) Start(ctx context.Context, bindings []Binding, route OwnedRoute) error {
	if s == nil {
		return ErrAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.withdrawn || s.route != nil {
		return s.withdrawLocked(ErrAuthority)
	}
	if ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil {
		return s.withdrawLocked(ErrAuthority)
	}
	bounded, err := s.authority.ConstrainBindings(bindings, time.Now())
	if err != nil {
		return s.withdrawLocked(err)
	}
	// The supervisor context, not the one-shot Start call, owns route lifetime.
	start, cancel := context.WithCancel(s.ctx)
	stop := context.AfterFunc(ctx, cancel)
	s.route, err = StartRoute(start, s.authority.lease.JobId, bounded, route)
	stop()
	if err == nil && (ctx.Err() != nil || s.ctx.Err() != nil) {
		err = ErrAuthority
	}
	if err != nil {
		cancel()
		return s.withdrawLocked(err)
	}
	// start is a child of s.ctx and is cancelled permanently by withdrawal.
	s.bindings = cloneAuthorityBindings(bindings)
	s.installed = bindingDeadline(bounded)
	s.signal()
	return nil
}

func cloneAuthorityBindings(bindings []Binding) []Binding {
	result := append([]Binding(nil), bindings...)
	for i := range result {
		result[i].addresses = result[i].Addresses()
		result[i].permissions = result[i].Permissions()
	}
	return result
}

func bindingDeadline(bindings []Binding) time.Time {
	deadline := bindings[0].expires
	for _, binding := range bindings {
		if binding.expires.Before(deadline) {
			deadline = binding.expires
		}
	}
	return time.Unix(deadline.Unix(), 0)
}

// RefreshDNS cannot extend authority, change grants/caps, reset traffic budgets,
// or resume a route whose kernel/DNS deadline has already expired.
func (s *AuthorityRoute) RefreshDNS(ctx context.Context, bindings []Binding) error {
	if s == nil {
		return ErrAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.withdrawn || s.route == nil {
		return s.withdrawLocked(ErrAuthority)
	}
	return s.refreshLocked(ctx, bindings, true)
}

func (s *AuthorityRoute) refreshLocked(ctx context.Context, bindings []Binding, dnsRefresh bool) error {
	if ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil {
		return s.withdrawLocked(ErrAuthority)
	}
	bounded, err := s.authority.ConstrainBindings(bindings, time.Now())
	if err != nil {
		return s.withdrawLocked(err)
	}
	if _, err := s.route.DNS(); err != nil {
		return s.withdrawLocked(err)
	}
	deadline := bindingDeadline(bounded)
	if dnsRefresh || !deadline.Equal(s.installed) {
		if err := s.route.refresh(ctx, bounded, false); err != nil {
			return s.withdrawLocked(err)
		}
		s.installed = deadline
	}
	if dnsRefresh {
		s.bindings = cloneAuthorityBindings(bindings)
	}
	s.signal()
	return nil
}

// ServeDNS uses stable owned sockets. Socket/server failure withdraws the same
// supervisor, so a later positive observation cannot replace a failed route.
func (s *AuthorityRoute) ServeDNS(ctx context.Context, udp net.PacketConn, tcp net.Listener, peers []netip.Addr) error {
	if s == nil {
		return ErrAuthority
	}
	s.mu.Lock()
	if s.withdrawn || s.route == nil {
		err := s.withdrawLocked(ErrAuthority)
		s.mu.Unlock()
		return err
	}
	route := s.route
	s.mu.Unlock()
	err := ServeRouteDNS(ctx, route, udp, tcp, peers)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withdrawLocked(err)
}

func (s *AuthorityRoute) Withdraw() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withdrawLocked(nil)
}

// Close is retryable; a prior actuation failure stays visible until a complete
// teardown retry succeeds. Done alone is never a cleanup success assertion.
func (s *AuthorityRoute) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	_ = s.withdrawLocked(nil)
	if s.route != nil {
		err := s.route.Close()
		if err == nil {
			s.cleanupErr = nil
		} else {
			s.cleanupErr = errors.Join(s.cleanupErr, err)
		}
	}
	err := s.cleanupErr
	s.mu.Unlock()
	<-s.watched
	return err
}

func (s *AuthorityRoute) watch() {
	defer close(s.watched)
	for {
		s.mu.Lock()
		if s.withdrawn {
			s.mu.Unlock()
			return
		}
		var expiry <-chan time.Time
		var timer *time.Timer
		var routeDone <-chan struct{}
		if s.authority.seen {
			deadline, err := s.authority.Deadline(time.Now())
			if err != nil {
				_ = s.withdrawLocked(err)
				s.mu.Unlock()
				return
			}
			timer = time.NewTimer(max(time.Until(deadline), 0))
			expiry = timer.C
		}
		if s.route != nil {
			routeDone = s.route.done
		}
		s.mu.Unlock()
		select {
		case <-s.ctx.Done():
		case <-routeDone:
		case <-expiry:
		case <-s.wake:
			if timer != nil {
				timer.Stop()
			}
			continue
		}
		if timer != nil {
			timer.Stop()
		}
		s.mu.Lock()
		// A renewal may have raced with the old timer; recheck before revoking.
		_, err := s.authority.Deadline(time.Now())
		routeFailed := false
		if s.route != nil {
			select {
			case <-s.route.done:
				routeFailed = true
			default:
			}
		}
		if err != nil || s.ctx.Err() != nil || routeFailed {
			_ = s.withdrawLocked(ErrAuthority)
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
	}
}
