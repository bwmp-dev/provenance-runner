package networkpolicy

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrActuation = errors.New("network_actuation_failed")

// OwnedRoute is a trusted actuator for one exclusively owned routing namespace.
// Apply executes ONE atomic nft batch, never in the host or guest namespace.
// Disconnect must sever every job route before returning success, even if Apply
// failed. Both operations must honor cancellation. Implementations must retain
// namespace ownership independently of mutable paths or caller-supplied names.
// This interface is not evidence of namespace ownership or installed protection.
type OwnedRoute interface {
	Apply(context.Context, string) error
	Disconnect(context.Context) error
}

// RouteSession serializes installation, renewal and irreversible withdrawal.
// Its DNS view is published only after the corresponding rules were installed.
// It never grants authority, creates namespaces, or produces a runtime claim.
type RouteSession struct {
	mu                               sync.Mutex
	job                              string
	route                            OwnedRoute
	rules                            Firewall
	view                             *WorkloadDNS
	withdrawn, disconnected, removed bool
	wake                             chan struct{}
	done                             chan struct{}
	stop                             context.CancelFunc
	ctx                              context.Context
}

const routeOperationTimeout = 3 * time.Second

// StartRoute requires a fresh exclusively owned namespace with no exposed job
// route. On an installation failure it returns a withdrawn session as well as
// an error: the owner must still call Close and retain it until cleanup succeeds.
// Cancellation and expiry withdraw independently of the caller's refresh loop.
func StartRoute(ctx context.Context, job string, bindings []Binding, route OwnedRoute) (*RouteSession, error) {
	if ctx == nil || route == nil || ctx.Err() != nil {
		return nil, ErrPolicy
	}
	now := time.Now()
	rules, err := CompileFirewallWithDNS(job, bindings, now)
	if err != nil {
		return nil, err
	}
	view, err := NewWorkloadDNS(job, bindings, now)
	if err != nil {
		return nil, err
	}
	watch, stop := context.WithCancel(ctx)
	s := &RouteSession{job: job, route: route, rules: rules, view: view, wake: make(chan struct{}, 1), done: make(chan struct{}), stop: stop, ctx: watch}
	s.mu.Lock()
	err = s.apply(ctx, rules.Install())
	if err == nil && (ctx.Err() != nil || !time.Now().Before(rules.ExpiresAt())) {
		err = ErrExpired
	}
	if err != nil {
		err = errors.Join(err, s.withdrawLocked())
	}
	s.mu.Unlock()
	go s.watch(watch)
	return s, err
}

func (s *RouteSession) apply(ctx context.Context, program string) error {
	bounded, cancel := context.WithTimeout(ctx, routeOperationTimeout)
	defer cancel()
	if s.route.Apply(bounded, program) != nil || bounded.Err() != nil {
		return ErrActuation
	}
	return nil
}

// DNS returns only the current installed view. Old views are permanently denied
// before renewal begins. The owner must separately expose owned DNS sockets and
// withdraw the session if their server fails; this method opens no listeners.
func (s *RouteSession) DNS() (*WorkloadDNS, error) {
	if s == nil {
		return nil, ErrPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.withdrawn || s.ctx.Err() != nil || !time.Now().Before(s.rules.ExpiresAt()) {
		return nil, ErrExpired
	}
	return s.view, nil
}

// Refresh replaces the whole still-live snapshot atomically without resetting
// counters, connection tracking or byte budgets. ANY failed renewal permanently
// withdraws this session, including invalid input or ambiguous actuator failure.
func (s *RouteSession) Refresh(ctx context.Context, bindings []Binding) error {
	if s == nil {
		return ErrPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.withdrawn {
		return ErrExpired
	}
	fail := func(err error) error { return errors.Join(err, s.withdrawLocked()) }
	if ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil {
		return fail(ErrPolicy)
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer func() { stop(); cancel() }()
	now := time.Now()
	next, err := CompileFirewallWithDNS(s.job, bindings, now)
	if err != nil {
		return fail(err)
	}
	view, err := NewWorkloadDNS(s.job, bindings, now)
	if err != nil {
		return fail(err)
	}
	program, err := s.rules.Refresh(next, now)
	if err != nil {
		return fail(err)
	}
	s.view.Withdraw()
	if err := s.apply(ctx, program); err != nil {
		return fail(err)
	}
	if ctx.Err() != nil || s.ctx.Err() != nil || !time.Now().Before(next.ExpiresAt()) {
		return fail(ErrExpired)
	}
	s.rules, s.view = next, view
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

func (s *RouteSession) withdrawLocked() error {
	s.withdrawn = true
	s.view.Withdraw()
	// Cleanup must not inherit an already-cancelled job context. An ambiguous
	// firewall result never prevents the independent route-disconnection attempt.
	program, err := s.rules.Withdraw()
	if err == nil {
		err = s.apply(context.Background(), program)
	}
	if !s.disconnected {
		ctx, cancel := context.WithTimeout(context.Background(), routeOperationTimeout)
		if s.route.Disconnect(ctx) != nil {
			err = errors.Join(err, ErrActuation)
		} else {
			s.disconnected = true
		}
		cancel()
	}
	return err
}

// Withdraw is irreversible. It retains default-drop rules and budget objects;
// Close may delete the table only after the independently owned route is severed.
func (s *RouteSession) Withdraw() error {
	if s == nil {
		return ErrPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.removed {
		return nil
	}
	err := s.withdrawLocked()
	s.stop()
	return err
}

// Close is retryable on cleanup failure. A failed disconnect must NEVER delete
// the default-drop table. The namespace owner remains responsible for retaining
// and destroying its resources; a return error cannot be treated as release.
func (s *RouteSession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.removed {
		s.mu.Unlock()
		<-s.done
		return nil
	}
	err := s.withdrawLocked()
	s.stop()
	if s.disconnected {
		if removeErr := s.apply(context.Background(), s.rules.Remove()); removeErr != nil {
			err = errors.Join(err, removeErr)
		} else {
			s.removed = true
		}
	}
	s.mu.Unlock()
	<-s.done
	return err
}

func (s *RouteSession) watch(ctx context.Context) {
	defer close(s.done)
	for {
		s.mu.Lock()
		if s.withdrawn {
			s.mu.Unlock()
			return
		}
		delay := time.Until(s.rules.ExpiresAt())
		s.mu.Unlock()
		timer := time.NewTimer(max(delay, 0))
		select {
		case <-ctx.Done():
			timer.Stop()
			s.mu.Lock()
			if !s.withdrawn {
				_ = s.withdrawLocked()
			}
			s.mu.Unlock()
			return
		case <-s.wake:
			timer.Stop()
		case <-timer.C:
			s.mu.Lock()
			if !s.withdrawn && !time.Now().Before(s.rules.ExpiresAt()) {
				_ = s.withdrawLocked()
			}
			s.mu.Unlock()
		}
	}
}
