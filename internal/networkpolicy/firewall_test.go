package networkpolicy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func firewallBinding(t *testing.T) (Binding, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 13, 2, 0, 0, 500000000, time.UTC)
	b := binder(t, responder(nil))
	b.now = func() time.Time { return now }
	binding, err := b.Resolve(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return binding, now
}

func TestFirewallSnapshotScopeAndExpiry(t *testing.T) {
	binding, now := firewallBinding(t)
	f, err := CompileFirewall(binding.job, []Binding{binding}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"create table inet pv_10000000000040008000000000000001\n",
		"type ipv4_addr . inet_proto . inet_service",
		"type ipv6_addr . inet_proto . inet_service",
		"1.1.1.1 . tcp . 443", "1.1.1.1 . udp . 8443",
		"2606:4700:4700::1111 . tcp . 443",
		"ct state new add @connections { meta mark ct count over 16 }",
		"rate over 1048576 bytes/second burst 0 bytes",
		"ct direction reply ct state established",
		"hook input priority 0; policy drop", "hook output priority 0; policy drop", "hook forward priority 0; policy drop",
	} {
		if !strings.Contains(f.Install(), fragment) {
			t.Errorf("missing %q", fragment)
		}
	}
	if strings.Contains(f.Install(), "flush") || strings.Contains(f.Install(), "include") || strings.Count(f.Install(), "add limit ") != 1 || strings.Count(f.Install(), "ct count") != 1 {
		t.Fatal("unsafe scope or split limits")
	}
	if f.Remove() != "delete table inet pv_10000000000040008000000000000001\n" || !f.ExpiresAt().Equal(binding.expires.Truncate(time.Second)) {
		t.Fatal("cleanup/expiry does not match owned snapshot")
	}
	if strings.Index(f.Install(), "meta time >= ") > strings.Index(f.Install(), "counter name forwarded accept") {
		t.Fatal("expiry must precede every accept, including established")
	}
	// Returned program does not retain mutable caller collections.
	before := f.Install()
	binding.addresses[0] = netip.MustParseAddr("1.0.0.1")
	if f.Install() != before {
		t.Fatal("snapshot mutated")
	}
}

func TestFirewallRejectsInvalidSnapshots(t *testing.T) {
	for name, mutate := range map[string]func(*Binding){
		"foreign job":         func(b *Binding) { b.job = "20000000-0000-4000-8000-000000000001" },
		"missing addresses":   func(b *Binding) { b.addresses = nil },
		"private address":     func(b *Binding) { b.addresses = []netip.Addr{netip.MustParseAddr("10.1.2.3")} },
		"mapped address":      func(b *Binding) { b.addresses = []netip.Addr{netip.MustParseAddr("::ffff:1.1.1.1")} },
		"missing permissions": func(b *Binding) { b.permissions = nil },
		"hostname injection":  func(b *Binding) { b.hostname = "a.example.com; accept"; b.permissions[0].Hostname = b.hostname },
		"protocol injection":  func(b *Binding) { b.permissions[0].Protocol = "tcp; accept" },
		"arbitrary DNS":       func(b *Binding) { b.permissions[0].Port = 53 },
		"zero connections":    func(b *Binding) { b.limits.Connections = 0 },
		"excess connections":  func(b *Binding) { b.limits.Connections = 1 << 32 },
		"zero bandwidth":      func(b *Binding) { b.limits.BytesPerSecond = 0 },
		"excess bandwidth":    func(b *Binding) { b.limits.BytesPerSecond = 1<<40 + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			b, now := firewallBinding(t)
			mutate(&b)
			f, err := CompileFirewall(options().JobID, []Binding{b}, now)
			if !errors.Is(err, ErrPolicy) || f.Install() != "" || f.Remove() != "" {
				t.Fatalf("partial or accepted invalid program: %+v %v", f, err)
			}
		})
	}
	b, now := firewallBinding(t)
	for _, job := range []string{"", "00000000-0000-0000-0000-000000000000", b.job + "; flush ruleset"} {
		if _, err := CompileFirewall(job, []Binding{b}, now); !errors.Is(err, ErrPolicy) {
			t.Fatal("accepted invalid job", err)
		}
	}
	for _, bindings := range [][]Binding{nil, {b, b}, make([]Binding, 129)} {
		if _, err := CompileFirewall(b.job, bindings, now); !errors.Is(err, ErrPolicy) {
			t.Fatal("accepted invalid collection", err)
		}
	}
	for _, when := range []time.Time{now.Add(-time.Second), b.expires, b.expires.Add(time.Second), b.expires.Truncate(time.Second)} {
		if _, err := CompileFirewall(b.job, []Binding{b}, when); !errors.Is(err, ErrExpired) {
			t.Fatal("accepted expired/future-issued/subsecond program", err)
		}
	}
}

func TestFirewallEarliestExpiryAndDeterministicTuples(t *testing.T) {
	b, now := firewallBinding(t)
	c, _ := firewallBinding(t)
	c.hostname = "other.example.com"
	for i := range c.permissions {
		c.permissions[i].Hostname = c.hostname
	}
	c.expires = now.Add(10 * time.Second)
	first, err := CompileFirewall(b.job, []Binding{b, c}, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileFirewall(b.job, []Binding{c, b}, now)
	if err != nil || first.Install() != second.Install() || !first.ExpiresAt().Equal(c.expires.Truncate(time.Second)) {
		t.Fatal("nondeterministic/extended grant", err)
	}
	c.limits.Connections++
	if _, err := CompileFirewall(b.job, []Binding{b, c}, now); !errors.Is(err, ErrPolicy) {
		t.Fatal("mixed effective limits accepted", err)
	}
}

func TestFirewallBoundsPacketTupleExpansion(t *testing.T) {
	b, now := firewallBinding(t)
	b.addresses = nil
	b.permissions = nil
	for i := 1; i <= 64; i++ {
		b.addresses = append(b.addresses, netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i)))
	}
	for port := uint16(10000); port < 10065; port++ {
		b.permissions = append(b.permissions, Permission{b.hostname, port, "tcp"})
	}
	if _, err := CompileFirewall(b.job, []Binding{b}, now); !errors.Is(err, ErrPolicy) {
		t.Fatal("expanded tuple limit not enforced", err)
	}
	b.permissions = b.permissions[:64]
	if _, err := CompileFirewall(b.job, []Binding{b}, now); err != nil {
		t.Fatal("exact tuple limit rejected", err)
	}
	b.expires = b.issued.Add(6 * time.Minute)
	if _, err := CompileFirewall(b.job, []Binding{b}, now); !errors.Is(err, ErrPolicy) {
		t.Fatal("excess binding lifetime accepted", err)
	}
}
