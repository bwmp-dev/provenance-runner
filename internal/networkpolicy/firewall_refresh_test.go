package networkpolicy

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRefreshPreservesBudgetObjectsAndDefaultDrop(t *testing.T) {
	binding, now := firewallBinding(t)
	before, err := CompileFirewall(binding.job, []Binding{binding}, now)
	if err != nil {
		t.Fatal(err)
	}
	binding.issued = binding.issued.Add(time.Second)
	binding.expires = binding.expires.Add(time.Second)
	after, err := CompileFirewall(binding.job, []Binding{binding}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	program, err := before.Refresh(after, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, denied := range []string{"delete table", "create table", "flush ruleset", "add chain", "delete chain", "add limit", "delete limit", "add counter", "delete counter", "delete set inet " + before.table + " connections"} {
		if strings.Contains(program, denied) {
			t.Fatalf("refresh resets enforcement state: %s", denied)
		}
	}
	if !strings.HasPrefix(program, "flush chain inet "+before.table+" forward\n") ||
		strings.Count(program, "delete set ") != 2 || strings.Count(program, "add set ") != 2 ||
		!strings.HasSuffix(program, after.rules) {
		t.Fatal("incomplete atomic grant replacement")
	}
	withdraw, err := before.Withdraw()
	if err != nil || withdraw != "flush chain inet "+before.table+" forward\n" {
		t.Fatal(withdraw, err)
	}
}

func TestRefreshRefusesChangedGrantOrLimits(t *testing.T) {
	for name, mutate := range map[string]func(*Binding){
		"job":         func(b *Binding) { b.job = "20000000-0000-4000-8000-000000000001" },
		"address":     func(b *Binding) { b.addresses = []netip.Addr{netip.MustParseAddr("1.0.0.1")} },
		"port":        func(b *Binding) { b.permissions[0].Port = 8080 },
		"connections": func(b *Binding) { b.limits.Connections++ },
		"bandwidth":   func(b *Binding) { b.limits.BytesPerSecond++ },
	} {
		t.Run(name, func(t *testing.T) {
			binding, now := firewallBinding(t)
			before, err := CompileFirewall(binding.job, []Binding{binding}, now)
			if err != nil {
				t.Fatal(err)
			}
			binding.issued = binding.issued.Add(time.Second)
			binding.expires = binding.expires.Add(time.Second)
			mutate(&binding)
			after, err := CompileFirewall(binding.job, []Binding{binding}, now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if program, err := before.Refresh(after, now.Add(time.Second)); !errors.Is(err, ErrPolicy) || program != "" {
				t.Fatal("changed grant accepted", err)
			}
		})
	}
}

func TestRefreshRefusesExpiredFutureAndZeroSnapshots(t *testing.T) {
	binding, now := firewallBinding(t)
	before, _ := CompileFirewall(binding.job, []Binding{binding}, now)
	binding.issued = binding.issued.Add(time.Second)
	binding.expires = binding.expires.Add(time.Second)
	after, _ := CompileFirewall(binding.job, []Binding{binding}, now.Add(time.Second))
	for _, at := range []time.Time{{}, now.Add(-time.Second), now, before.ExpiresAt(), after.ExpiresAt()} {
		if program, err := before.Refresh(after, at); !errors.Is(err, ErrExpired) || program != "" {
			t.Fatal("invalid time accepted", at, err)
		}
	}
	if _, err := before.Refresh(before, now); !errors.Is(err, ErrExpired) {
		t.Fatal("non-renewal accepted", err)
	}
	if _, err := (Firewall{}).Refresh(after, now); !errors.Is(err, ErrPolicy) {
		t.Fatal(err)
	}
	if _, err := before.Refresh(Firewall{}, now); !errors.Is(err, ErrPolicy) {
		t.Fatal(err)
	}
	if _, err := (Firewall{}).Withdraw(); !errors.Is(err, ErrPolicy) {
		t.Fatal(err)
	}
}
