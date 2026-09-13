package networkpolicy

import (
	"strings"
	"testing"
	"time"
)

func TestDNSFirewallExactOwnedChannelAndSharedBudgets(t *testing.T) {
	binding, now := firewallBinding(t)
	legacy, err := CompileFirewall(binding.job, []Binding{binding}, now)
	if err != nil {
		t.Fatal(err)
	}
	controlled, err := CompileFirewallWithDNS(binding.job, []Binding{binding}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(controlled.Install(), legacy.Install()) || strings.Contains(legacy.Install(), "dport 53") {
		t.Fatal("legacy rules changed")
	}
	for _, required := range []string{
		`iifname "job0" ct direction original ip saddr 10.0.1.2 ip daddr 10.0.1.1 udp dport 53`,
		`iifname "job0" ct direction original ip saddr 10.0.1.2 ip daddr 10.0.1.1 tcp dport 53`,
		`oifname "job0" ct direction reply ct state established ip saddr 10.0.1.1 ip daddr 10.0.1.2 udp sport 53`,
		`oifname "job0" ct direction reply ct state established ip saddr 10.0.1.1 ip daddr 10.0.1.2 tcp sport 53`,
	} {
		if !strings.Contains(controlled.dnsRules, required) {
			t.Fatal("missing exact DNS rule", required)
		}
	}
	if strings.Count(controlled.Install(), "add limit ") != 1 || strings.Count(controlled.Install(), "add set inet "+controlled.table+" connections") != 1 || strings.Count(controlled.Install(), "limit name bandwidth") != 3 {
		t.Fatal("DNS acquired independent budgets")
	}
	binding.issued = binding.issued.Add(time.Second)
	binding.expires = binding.expires.Add(time.Second)
	next, err := CompileFirewallWithDNS(binding.job, []Binding{binding}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := controlled.Refresh(next, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range []string{"input", "output", "forward"} {
		if !strings.Contains(refresh, "flush chain inet "+controlled.table+" "+chain+"\n") {
			t.Fatal("stale DNS expiry retained")
		}
	}
	for _, forbidden := range []string{"add limit", "delete limit", "add counter", "create table", "delete table", "add set inet " + controlled.table + " connections"} {
		if strings.Contains(refresh, forbidden) {
			t.Fatal("DNS refresh reset shared budgets")
		}
	}
	withdraw, err := next.Withdraw()
	if err != nil || strings.Count(withdraw, "flush chain ") != 3 {
		t.Fatal("DNS survived withdrawal")
	}
	if _, err := legacy.Refresh(next, now.Add(time.Second)); err == nil {
		t.Fatal("refresh changed DNS profile")
	}
	if _, err := CompileFirewallWithDNS(binding.job, nil, now); err == nil {
		t.Fatal("none acquired DNS")
	}
}
