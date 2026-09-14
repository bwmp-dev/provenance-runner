package networkpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type authorityRecordingRoute struct {
	recordingRoute
	job string
}

func (r *authorityRecordingRoute) JobID() string { return r.job }

func authorityRouteFixture(t *testing.T) (*AuthorityRoute, *p.LeaseReconciliation, []p.ProtocolFeature, time.Time, []Binding, *authorityRecordingRoute) {
	t.Helper()
	_, job, receipt, features, _, _ := authorityFixture(t)
	now := time.Now()
	job.Lease.ExpiresAt = timestamppb.New(now.Add(2 * time.Minute))
	receipt.Lease.ExpiresAt = proto.Clone(job.Lease.ExpiresAt).(*timestamppb.Timestamp)
	receipt.NetworkAuthorityV2.CheckedAt = timestamppb.New(now)
	receipt.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(40 * time.Second))
	s, err := NewAuthorityRoute(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, receipt, features, now.Add(2 * time.Minute), authorityBindings(s.authority, now), &authorityRecordingRoute{job: job.Lease.JobId}
}

func startAuthorityRoute(t *testing.T, s *AuthorityRoute, r *p.LeaseReconciliation, f []p.ProtocolFeature, c time.Time, b []Binding, route OwnedRoute) {
	t.Helper()
	if err := s.Reconcile(context.Background(), r, f, c); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background(), b, route); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityRouteRequiresFreshAuthorityAndNeverResumes(t *testing.T) {
	s, r, f, c, b, route := authorityRouteFixture(t)
	if err := s.Start(context.Background(), b, route); err == nil {
		t.Fatal("unobserved authority installed")
	}
	if len(route.records()) != 0 {
		t.Fatal("touched route without authority")
	}
	if err := s.Reconcile(context.Background(), r, f, c); err == nil {
		t.Fatal("failed attempt resumed")
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("withdrawal not signalled")
	}
}

func TestAuthorityRouteDeadlineReductionAndRenewalPreserveBudgets(t *testing.T) {
	s, r, f, c, b, route := authorityRouteFixture(t)
	startAuthorityRoute(t, s, r, f, c, b, route)
	old, err := s.route.DNS()
	if err != nil {
		t.Fatal(err)
	}
	r.NetworkAuthorityV2.CheckedAt = timestamppb.New(time.Now())
	r.NetworkAuthorityV2.ExpiresAt = timestamppb.New(time.Now().Add(12 * time.Second))
	if err := s.Reconcile(context.Background(), r, f, c); err != nil {
		t.Fatal(err)
	}
	deadline := r.NetworkAuthorityV2.ExpiresAt.AsTime().Unix()
	program := route.records()[1]
	if strings.Count(program, fmt.Sprintf("meta time >= %d counter drop", deadline)) != 3 {
		t.Fatal("forward and both DNS chains not reduced", program)
	}
	for _, denied := range []string{"create table", "delete table", "add counter", "add limit", "add chain", " connections"} {
		if strings.Contains(program, denied) {
			t.Fatal("traffic budget reset", denied)
		}
	}
	old.mu.Lock()
	withdrawn := old.withdrawn
	old.mu.Unlock()
	if !withdrawn {
		t.Fatal("old DNS survived replacement")
	}
	for _, binding := range s.route.view.bindings {
		if binding.expires.After(r.NetworkAuthorityV2.ExpiresAt.AsTime()) {
			t.Fatal("DNS exceeds reduced authority")
		}
	}
	r.NetworkAuthorityV2.CheckedAt = timestamppb.New(time.Now())
	r.NetworkAuthorityV2.ExpiresAt = timestamppb.New(time.Now().Add(50 * time.Second))
	if err := s.Reconcile(context.Background(), r, f, c); err != nil {
		t.Fatal(err)
	}
	if len(route.records()) != 3 || !s.installed.Equal(time.Unix(r.NetworkAuthorityV2.ExpiresAt.AsTime().Unix(), 0)) {
		t.Fatal("fresh authority not installed")
	}
	// An unchanged receipt is not a kernel refresh and cannot refill budgets.
	if err := s.Reconcile(context.Background(), r, f, c); err != nil {
		t.Fatal(err)
	}
	if len(route.records()) != 3 {
		t.Fatal("duplicate receipt reinstalled")
	}
	// DNS expiry can never extend the authority deadline.
	b[0].expires = b[0].expires.Add(time.Minute)
	if err := s.RefreshDNS(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if !s.installed.Equal(time.Unix(r.NetworkAuthorityV2.ExpiresAt.AsTime().Unix(), 0)) {
		t.Fatal("DNS extended authority")
	}
}

func TestAuthorityRouteWithdrawalAndActuationFailureRemainOwned(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			s, r, f, c, b, route := authorityRouteFixture(t)
			startAuthorityRoute(t, s, r, f, c, b, route)
			route.mu.Lock()
			route.failApply = failure
			route.failDisconnect = failure
			route.mu.Unlock()
			r.NetworkAuthorityV2.State = p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_WITHDRAWN
			r.NetworkAuthorityV2.ExpiresAt = nil
			if err := s.Reconcile(context.Background(), r, f, c); err == nil {
				t.Fatal("withdrawal did not stop owner")
			}
			select {
			case <-s.Done():
			default:
				t.Fatal("worker not stopped")
			}
			if _, err := s.route.DNS(); err == nil {
				t.Fatal("withdrawn DNS")
			}
			if err := s.Close(); failure && !errors.Is(err, ErrActuation) {
				t.Fatal("cleanup failure lost", err)
			}
			for _, program := range route.records() {
				if failure && strings.HasPrefix(program, "delete table") {
					t.Fatal("removed protection before disconnect")
				}
			}
			route.mu.Lock()
			route.failApply = false
			route.failDisconnect = false
			route.mu.Unlock()
			if err := s.Close(); err != nil {
				t.Fatal("owned cleanup retry failed", err)
			}
			r.NetworkAuthorityV2.State = p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT
			r.NetworkAuthorityV2.ExpiresAt = timestamppb.New(time.Now().Add(30 * time.Second))
			if err := s.Reconcile(context.Background(), r, f, c); err == nil {
				t.Fatal("withdrawn attempt resumed")
			}
		})
	}
}

func TestAuthorityRouteExpiryBeforeAndAfterInstallation(t *testing.T) {
	for _, install := range []bool{false, true} {
		t.Run(fmt.Sprint(install), func(t *testing.T) {
			s, r, f, c, b, route := authorityRouteFixture(t)
			// Two whole seconds leave enough room for the kernel's conservative
			// whole-second deadline, without weakening its absolute expiry.
			r.NetworkAuthorityV2.ExpiresAt = timestamppb.New(time.Now().Add(2 * time.Second))
			if err := s.Reconcile(context.Background(), r, f, c); err != nil {
				t.Fatal(err)
			}
			if install {
				if err := s.Start(context.Background(), b, route); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-s.Done():
			case <-time.After(4 * time.Second):
				t.Fatal("expiry needs caller polling")
			}
			r.NetworkAuthorityV2.CheckedAt = timestamppb.New(time.Now())
			r.NetworkAuthorityV2.ExpiresAt = timestamppb.New(time.Now().Add(30 * time.Second))
			if err := s.Reconcile(context.Background(), r, f, c); err == nil {
				t.Fatal("expired attempt resumed")
			}
		})
	}
}

func TestAuthorityRouteConcurrentRefreshAndWithdrawal(t *testing.T) {
	s, r, f, c, b, route := authorityRouteFixture(t)
	startAuthorityRoute(t, s, r, f, c, b, route)
	var group sync.WaitGroup
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 20 {
				_ = s.Reconcile(context.Background(), r, f, c)
				_ = s.RefreshDNS(context.Background(), b)
			}
		}()
	}
	_ = s.Withdraw()
	group.Wait()
	if err := s.Reconcile(context.Background(), r, f, c); err == nil {
		t.Fatal("concurrent resume")
	}
	if _, err := s.route.DNS(); err == nil {
		t.Fatal("concurrent DNS resume")
	}
}

func TestAuthorityRouteInvalidRefreshWithdrawsInstalledRoute(t *testing.T) {
	for _, kind := range []string{"missing metadata", "downgrade", "changed binding", "cancelled refresh", "actuation", "DNS server"} {
		t.Run(kind, func(t *testing.T) {
			s, r, f, c, b, route := authorityRouteFixture(t)
			startAuthorityRoute(t, s, r, f, c, b, route)
			var err error
			switch kind {
			case "missing metadata":
				r.NetworkAuthorityV2 = nil
				err = s.Reconcile(context.Background(), r, f, c)
			case "downgrade":
				err = s.Reconcile(context.Background(), r, []p.ProtocolFeature{1, 3, 9}, c)
			case "changed binding":
				b[0].permissions[0].Port++
				err = s.RefreshDNS(context.Background(), b)
			case "cancelled refresh":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				err = s.RefreshDNS(ctx, b)
			case "actuation":
				route.mu.Lock()
				route.failApply = true
				route.mu.Unlock()
				err = s.RefreshDNS(context.Background(), b)
				route.mu.Lock()
				route.failApply = false
				route.mu.Unlock()
			case "DNS server":
				err = s.ServeDNS(context.Background(), nil, nil, nil)
			}
			if err == nil {
				t.Fatal("invalid input accepted")
			}
			select {
			case <-s.Done():
			default:
				t.Fatal("owner not stopped")
			}
			if _, err := s.route.DNS(); err == nil {
				t.Fatal("network not withdrawn")
			}
			if err := s.RefreshDNS(context.Background(), b); err == nil {
				t.Fatal("invalid route resumed")
			}
		})
	}
}

func TestAuthorityRouteInstallFailureRetainsCleanupAndContextOwnership(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			s, r, f, c, b, route := authorityRouteFixture(t)
			if err := s.Reconcile(context.Background(), r, f, c); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			route.beforeApply = func(_ context.Context, program string) {
				if strings.HasPrefix(program, "create table") && cancelled {
					cancel()
				}
			}
			route.failApply = !cancelled
			route.failDisconnect = true
			if err := s.Start(ctx, b, route); err == nil {
				t.Fatal("failed install accepted")
			}
			if s.route == nil {
				t.Fatal("partial install ownership lost")
			}
			if err := s.Close(); !errors.Is(err, ErrActuation) {
				t.Fatal("failed disconnect lost", err)
			}
			route.mu.Lock()
			route.failApply = false
			route.failDisconnect = false
			route.mu.Unlock()
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
