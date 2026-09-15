//go:build linux

package gvisor

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"golang.org/x/net/dns/dnsmessage"
)

type sessionDNSResolverFixture struct{ fail, changed atomic.Bool }

func (r *sessionDNSResolverFixture) Exchange(ctx context.Context, raw []byte) ([]byte, error) {
	if ctx.Err() != nil || r.fail.Load() {
		return nil, np.ErrDNS
	}
	reply, err := (measuredResolver{}).Exchange(ctx, raw)
	if err != nil || !r.changed.Load() {
		return reply, err
	}
	var message dnsmessage.Message
	if message.Unpack(reply) != nil {
		return nil, np.ErrDNS
	}
	for i := range message.Answers {
		if message.Answers[i].Header.Type == dnsmessage.TypeA {
			message.Answers[i].Body = &dnsmessage.AResource{A: netip.MustParseAddr("1.0.0.1").As4()}
		}
	}
	return message.Pack()
}

func TestMeasuredSessionDNSPinsAndCopiesBoundary(t *testing.T) {
	job := measuredSpecJob(t)
	local := np.LocalV2Boundary{Maximum: job.EffectivePolicy.NetworkV2, SensitiveNetworks: []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}, MaximumTTL: 4 * time.Second}
	resolver := &sessionDNSResolverFixture{}
	s, err := newMeasuredSessionDNS(job, local, resolver)
	if err != nil {
		t.Fatal(err)
	}
	job.EffectivePolicy.NetworkV2.Permissions[0].Hostname = "mutated.example.com"
	local.SensitiveNetworks[0] = netip.MustParsePrefix("1.1.1.1/32")
	bindings, err := s.resolve(context.Background())
	if err != nil || len(bindings) != 1 || bindings[0].Hostname() != "fixture.example.com" {
		t.Fatal("mutable DNS boundary", err)
	}
	if delay, err := sessionDNSRefreshDelay(bindings, time.Now()); err != nil || delay <= 0 || delay > 2*time.Second {
		t.Fatal("renewal outside TTL", err)
	}
	if _, err := sessionDNSRefreshDelay(bindings, bindings[0].ExpiresAt().Truncate(time.Second)); err == nil {
		t.Fatal("kernel-expired binding renewed")
	}
	resolver.changed.Store(true)
	if _, err := s.resolve(context.Background()); err == nil {
		t.Fatal("rebind admitted")
	}
	resolver.changed.Store(false)
	if _, err := s.resolve(context.Background()); err == nil {
		t.Fatal("poisoned pin resumed")
	}
}

func TestMeasuredSessionDNSRefusesInvalidAndCancelledInputs(t *testing.T) {
	job := measuredSpecJob(t)
	if s, err := newMeasuredSessionDNS(job, np.LocalV2Boundary{}, measuredResolver{}); s != nil || err == nil {
		t.Fatal("missing local maximum admitted")
	}
	var absent *measuredSessionDNS
	if _, err := absent.resolve(context.Background()); err == nil {
		t.Fatal("missing binder admitted")
	}
	if _, err := sessionDNSRefreshDelay(nil, time.Now()); err == nil {
		t.Fatal("missing expiry admitted")
	}
	local := np.LocalV2Boundary{Maximum: job.EffectivePolicy.NetworkV2, SensitiveNetworks: []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}, MaximumTTL: 4 * time.Second}
	s, err := newMeasuredSessionDNS(job, local, measuredResolver{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.resolve(ctx); err == nil {
		t.Fatal("cancelled resolution admitted")
	}
	job.Hashes.Policy.Value[0] ^= 1
	if s, err := newMeasuredSessionDNS(job, local, measuredResolver{}); s != nil || err == nil {
		t.Fatal("unfrozen policy admitted")
	}
}
