package networkpolicy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type recordingRoute struct {
	mu                        sync.Mutex
	programs                  []string
	failApply, failDisconnect bool
	beforeApply               func(context.Context, string)
}

func (r *recordingRoute) Apply(ctx context.Context, program string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded route operation")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.programs = append(r.programs, program)
	if r.beforeApply != nil {
		r.beforeApply(ctx, program)
	}
	if r.failApply {
		return errors.New("synthetic actuator error, do not disclose")
	}
	return nil
}
func (r *recordingRoute) Disconnect(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded disconnect")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.programs = append(r.programs, "disconnect")
	if r.failDisconnect {
		return ErrActuation
	}
	return nil
}
func (r *recordingRoute) records() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.programs...)
}
func liveRouteBinding(t *testing.T) Binding {
	t.Helper()
	b := binder(t, responder(nil))
	value, err := b.Resolve(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func routeDNSAnswers(t *testing.T, view *WorkloadDNS) int {
	t.Helper()
	raw, err := view.Answer(workloadQuery(t, "api.example.com", dnsmessage.TypeA), false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var message dnsmessage.Message
	if message.Unpack(raw) != nil {
		t.Fatal("invalid response")
	}
	return len(message.Answers)
}

func TestRouteSessionInstalledDNSRefreshAndCleanup(t *testing.T) {
	binding := liveRouteBinding(t)
	route := &recordingRoute{}
	s, err := StartRoute(context.Background(), binding.job, []Binding{binding}, route)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	view, err := s.DNS()
	if err != nil || routeDNSAnswers(t, view) != 1 {
		t.Fatal("installed DNS unavailable", err)
	}
	if calls := route.records(); len(calls) != 1 || !strings.HasPrefix(calls[0], "create table") {
		t.Fatal("not installed first")
	}
	binding.expires = binding.expires.Add(time.Second)
	route.beforeApply = func(_ context.Context, program string) {
		if strings.HasPrefix(program, "flush chain") && routeDNSAnswers(t, view) != 0 {
			t.Error("old DNS exposed while rules change")
		}
	}
	if err := s.Refresh(context.Background(), []Binding{binding}); err != nil {
		t.Fatal(err)
	}
	next, err := s.DNS()
	if err != nil || next == view || routeDNSAnswers(t, next) != 1 || routeDNSAnswers(t, view) != 0 {
		t.Fatal("DNS publication boundary", err)
	}
	refresh := route.records()[1]
	for _, denied := range []string{"create table", "delete table", "add limit", "add counter", "add chain", "delete set inet " + s.rules.table + " connections"} {
		if strings.Contains(refresh, denied) {
			t.Fatal("renewal resets budget", denied)
		}
	}
	if err := s.Withdraw(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DNS(); err == nil || routeDNSAnswers(t, next) != 0 {
		t.Fatal("withdrawn DNS accepted")
	}
	if err := s.Refresh(context.Background(), []Binding{binding}); !errors.Is(err, ErrExpired) {
		t.Fatal("resumed withdrawn session")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	calls := route.records()
	disconnect, remove := -1, -1
	for i, call := range calls {
		if call == "disconnect" {
			disconnect = i
		}
		if strings.HasPrefix(call, "delete table") {
			remove = i
		}
	}
	if disconnect < 0 || remove <= disconnect {
		t.Fatal("removed protection before severing route")
	}
}

func TestRouteSessionFailedRenewalPermanentlyWithdraws(t *testing.T) {
	for _, kind := range []string{"invalid", "changed", "cancelled", "apply"} {
		t.Run(kind, func(t *testing.T) {
			binding := liveRouteBinding(t)
			route := &recordingRoute{}
			s, err := StartRoute(context.Background(), binding.job, []Binding{binding}, route)
			if err != nil {
				t.Fatal(err)
			}
			view, _ := s.DNS()
			binding.expires = binding.expires.Add(time.Second)
			bindings := []Binding{binding}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "invalid":
				bindings = nil
			case "changed":
				bindings[0].limits.Connections++
			case "cancelled":
				cancel()
			case "apply":
				route.failApply = true
			}
			if err := s.Refresh(ctx, bindings); err == nil {
				t.Fatal("failed refresh accepted")
			}
			if _, err := s.DNS(); err == nil || routeDNSAnswers(t, view) != 0 {
				t.Fatal("failure retains DNS authority")
			}
			calls := route.records()
			if calls[len(calls)-1] != "disconnect" {
				t.Fatal("failure did not disconnect", calls)
			}
			if err := s.Refresh(context.Background(), []Binding{binding}); err == nil {
				t.Fatal("failure was resumable")
			}
			route.mu.Lock()
			route.failApply = false
			route.mu.Unlock()
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRouteSessionDisconnectFailureRetainsDropAndAllowsCleanupRetry(t *testing.T) {
	binding := liveRouteBinding(t)
	route := &recordingRoute{failDisconnect: true}
	s, err := StartRoute(context.Background(), binding.job, []Binding{binding}, route)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); !errors.Is(err, ErrActuation) {
		t.Fatal("cleanup failure lost")
	}
	for _, call := range route.records() {
		if strings.HasPrefix(call, "delete table") {
			t.Fatal("removed protection while route exists")
		}
	}
	route.mu.Lock()
	route.failDisconnect = false
	route.mu.Unlock()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRouteSessionAmbiguousInstallFailureReturnsCleanupOwner(t *testing.T) {
	binding := liveRouteBinding(t)
	route := &recordingRoute{failApply: true, failDisconnect: true}
	s, err := StartRoute(context.Background(), binding.job, []Binding{binding}, route)
	if s == nil || !errors.Is(err, ErrActuation) || strings.Contains(err.Error(), "synthetic") {
		t.Fatal("unsafe install failure", err)
	}
	if _, err := s.DNS(); err == nil {
		t.Fatal("failed install exposed DNS")
	}
	route.mu.Lock()
	route.failApply, route.failDisconnect = false, false
	route.mu.Unlock()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRouteSessionCancellationAndExpiryWithdrawWithoutRefresh(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "expiry"}[expiry], func(t *testing.T) {
			binding := liveRouteBinding(t)
			if expiry {
				binding.expires = time.Now().Truncate(time.Second).Add(2 * time.Second)
			}
			route := &recordingRoute{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := StartRoute(ctx, binding.job, []Binding{binding}, route)
			if err != nil {
				t.Fatal(err)
			}
			if !expiry {
				cancel()
			}
			select {
			case <-s.done:
			case <-time.After(4 * time.Second):
				t.Fatal("lifecycle observer did not withdraw")
			}
			if _, err := s.DNS(); err == nil {
				t.Fatal("expired/cancelled DNS accepted")
			}
			calls := route.records()
			if calls[len(calls)-1] != "disconnect" {
				t.Fatal("observer did not sever route")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRouteSessionConcurrentRefreshWithdrawalNeverResumes(t *testing.T) {
	binding := liveRouteBinding(t)
	route := &recordingRoute{}
	s, err := StartRoute(context.Background(), binding.job, []Binding{binding}, route)
	if err != nil {
		t.Fatal(err)
	}
	binding.expires = binding.expires.Add(time.Second)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() { _ = s.Refresh(context.Background(), []Binding{binding}) })
		workers.Go(func() { _ = s.Withdraw() })
	}
	workers.Wait()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	seenDisconnect := false
	for _, call := range route.records() {
		if call == "disconnect" {
			seenDisconnect = true
		}
		if seenDisconnect && strings.Contains(call, "accept") {
			t.Fatal("granted traffic after disconnect")
		}
	}
}

func TestRouteSessionParentCancellationInterruptsInFlightRenewal(t *testing.T) {
	binding := liveRouteBinding(t)
	route := &recordingRoute{}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := StartRoute(parent, binding.job, []Binding{binding}, route)
	if err != nil {
		t.Fatal(err)
	}
	view, _ := s.DNS()
	binding.expires = binding.expires.Add(time.Second)
	route.beforeApply = func(ctx context.Context, program string) {
		if !strings.Contains(program, "delete set") {
			return
		}
		cancel()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Error("parent cancellation did not interrupt actuator")
		}
	}
	// The per-call context remains live: the session's original owner must still
	// be able to interrupt this transaction and refuse a new DNS publication.
	if err := s.Refresh(context.Background(), []Binding{binding}); err == nil {
		t.Fatal("renewed a cancelled owner")
	}
	if _, err := s.DNS(); err == nil || routeDNSAnswers(t, view) != 0 {
		t.Fatal("cancelled owner retained DNS")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRouteSessionInvalidStartDoesNotTouchActuator(t *testing.T) {
	binding := liveRouteBinding(t)
	for _, kind := range []string{"nil-context", "cancelled", "foreign-job", "expired"} {
		t.Run(kind, func(t *testing.T) {
			route := &recordingRoute{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var input context.Context = ctx
			job := binding.job
			value := binding
			switch kind {
			case "nil-context":
				input = nil
			case "cancelled":
				cancel()
			case "foreign-job":
				job = "20000000-0000-4000-8000-000000000001"
			case "expired":
				value.expires = time.Now().Add(-time.Second)
			}
			s, err := StartRoute(input, job, []Binding{value}, route)
			if s != nil || err == nil || len(route.records()) != 0 {
				t.Fatal("invalid start touched actuator")
			}
		})
	}
}
