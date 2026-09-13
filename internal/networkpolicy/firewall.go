package networkpolicy

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Firewall is an immutable, bounded nftables program for a dedicated routing
// namespace. It is NOT an actuator or authorization to configure a host. The
// namespace must contain only this job's two trusted veth endpoints (job0 and
// wan0), with the job using 10.0.1.2/fd00:1::2, forwarding enabled, no alternate
// route around it, and no other
// rules. In particular, installing this in the Sentry's OUTPUT path is unsafe:
// gVisor sends raw L2 packets that must traverse the routing namespace instead.
type Firewall struct {
	table, install, remove string
	expires                time.Time
}

func (f Firewall) Install() string      { return f.install }
func (f Firewall) Remove() string       { return f.remove }
func (f Firewall) ExpiresAt() time.Time { return f.expires }

// CompileFirewall constructs a fail-closed snapshot. Every binding must belong
// to the authenticated job and have identical effective limits. Earliest expiry
// closes the entire snapshot, including established connections. Refresh and
// teardown remain the future actuator's responsibility; never append refreshed
// grants beside stale rules. No production caller currently uses this program.
func CompileFirewall(job string, bindings []Binding, now time.Time) (Firewall, error) {
	if !jobID.MatchString(job) || job == "00000000-0000-0000-0000-000000000000" || now.IsZero() || len(bindings) == 0 || len(bindings) > 128 {
		return Firewall{}, ErrPolicy
	}
	limits := bindings[0].limits
	if limits.Connections == 0 || limits.Connections > 1<<32-1 || limits.BytesPerSecond == 0 || limits.BytesPerSecond > 1<<32-1 {
		return Firewall{}, ErrPolicy
	}
	expires := bindings[0].expires
	sets := [2]map[string]struct{}{{}, {}}
	names := make(map[string]bool)
	for _, binding := range bindings {
		if binding.job != job || binding.limits != limits || names[binding.hostname] || len(binding.addresses) == 0 || len(binding.addresses) > 64 || len(binding.permissions) == 0 || len(binding.permissions) > 128 || binding.expires.Sub(binding.issued) > 5*time.Minute {
			return Firewall{}, ErrPolicy
		}
		if !binding.ValidAt(now) {
			return Firewall{}, ErrExpired
		}
		names[binding.hostname] = true
		if binding.expires.Before(expires) {
			expires = binding.expires
		}
		for _, address := range binding.addresses {
			if !(&Binder{}).public(address) {
				return Firewall{}, ErrPolicy
			}
			family := 0
			if address.Is6() {
				family = 1
			}
			for _, permission := range binding.permissions {
				if permission.Hostname != binding.hostname || !hostname(permission.Hostname) || blockedPort(permission.Port) || (permission.Protocol != "tcp" && permission.Protocol != "udp") {
					return Firewall{}, ErrPolicy
				}
				sets[family][fmt.Sprintf("%s . %s . %d", address, permission.Protocol, permission.Port)] = struct{}{}
				if len(sets[0])+len(sets[1]) > 4096 {
					return Firewall{}, ErrPolicy
				}
			}
		}
	}
	// nft's absolute time is in Unix seconds. Round DOWN so queue/install latency
	// can never extend a DNS grant. Dates outside the kernel timestamp range fail.
	deadline := expires.Unix()
	if deadline <= now.Unix() || deadline <= 0 || deadline > 1<<32-1 {
		return Firewall{}, ErrExpired
	}
	table := "pv_" + strings.ReplaceAll(job, "-", "")
	var out strings.Builder
	fmt.Fprintf(&out, "create table inet %s\n", table)
	for family, entries := range sets {
		if len(entries) == 0 {
			continue
		}
		values := make([]string, 0, len(entries))
		for value := range entries {
			values = append(values, value)
		}
		sort.Strings(values)
		fmt.Fprintf(&out, "add set inet %s allowed%d { type ipv%d_addr . inet_proto . inet_service; flags timeout; timeout %dms; size 4096; elements = { %s }; }\n", table, 4+family*2, 4+family*2, expires.Sub(now).Milliseconds(), strings.Join(values, ", "))
	}
	fmt.Fprintf(&out, "add set inet %s connections { type mark; flags dynamic; size 1; }\n", table)
	fmt.Fprintf(&out, "add counter inet %s forwarded\nadd counter inet %s bandwidth_denied\n", table, table)
	// A single shared token bucket covers both address families and both
	// directions. nft's byte bucket holds rate+burst, so explicit zero additional
	// burst yields a one-second bucket, not two seconds of initial permission.
	fmt.Fprintf(&out, "add limit inet %s bandwidth { rate over %d bytes/second burst 0 bytes; }\n", table, limits.BytesPerSecond)
	for _, chain := range []string{"input", "output", "forward"} {
		fmt.Fprintf(&out, "add chain inet %s %s { type filter hook %s priority 0; policy drop; }\n", table, chain, chain)
	}
	rule := func(body string, args ...any) {
		fmt.Fprintf(&out, "add rule inet %s forward %s\n", table, fmt.Sprintf(body, args...))
	}
	rule("meta time >= %d counter drop", deadline)
	rule("ct state invalid,untracked counter drop")
	rule("limit name bandwidth counter name bandwidth_denied drop")
	// One constant key, not per-source/family/destination buckets. This is safe
	// only in the dedicated routing namespace, which owns the packet mark.
	rule("meta mark set 1")
	rule("ct state new add @connections { meta mark ct count over %d } counter drop", limits.Connections)
	for family, entries := range sets {
		if len(entries) == 0 {
			continue
		}
		ip := "ip"
		jobAddress := "10.0.1.2"
		if family == 1 {
			ip = "ip6"
			jobAddress = "fd00:1::2"
		}
		rule("iifname \"job0\" oifname \"wan0\" ct direction original %s saddr %s %s daddr . meta l4proto . th dport @allowed%d counter name forwarded accept", ip, jobAddress, ip, 4+family*2)
		rule("iifname \"wan0\" oifname \"job0\" ct direction reply ct state established %s daddr %s %s saddr . meta l4proto . th sport @allowed%d counter name forwarded accept", ip, jobAddress, ip, 4+family*2)
	}
	rule("counter drop")
	return Firewall{table: table, install: out.String(), remove: fmt.Sprintf("delete table inet %s\n", table), expires: time.Unix(deadline, 0)}, nil
}
