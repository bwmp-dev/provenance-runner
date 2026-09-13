// Package networkpolicy prepares bounded address bindings for future workload
// enforcement. It has no production callers and never installs packet rules.
package networkpolicy

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrPolicy    = errors.New("network_policy_invalid")
	ErrDenied    = errors.New("network_destination_denied")
	ErrDNS       = errors.New("network_dns_unavailable")
	ErrRebinding = errors.New("network_address_binding_changed")
	ErrExpired   = errors.New("network_address_binding_expired")
)

// Permission is one indivisible grant, not independent host/port/protocol sets.
type Permission struct {
	Hostname string
	Port     uint16
	Protocol string
}
type Limits struct{ Connections, BytesPerSecond uint64 }

// Options must come from authenticated, intersected policy plus the trusted
// operator's sensitive-network inventory. This internal type is NOT a wire
// format or a replacement for the platform's five-layer policy evaluation.
type Options struct {
	JobID             string
	Mode              string
	Permissions       []Permission
	Limits            Limits
	SensitiveNetworks []netip.Prefix
	MaximumTTL        time.Duration
}

// Exchange transports exactly one DNS message to an operator-selected resolver.
// It must respect cancellation and bound its response before returning bytes.
type Exchange interface {
	Exchange(context.Context, []byte) ([]byte, error)
}

type Binder struct {
	job         string
	permissions map[string][]Permission
	limits      Limits
	sensitive   []netip.Prefix
	maxTTL      time.Duration
	resolver    Exchange
	slot        chan struct{}
	pins        map[string][32]byte
	poisoned    map[string]bool
	now         func() time.Time
}

// Binding is immutable evidence of validated resolution, NOT packet permission.
// A future actuator must separately verify job ownership, install restrictions
// and caps, withdraw old rules on refresh failure, and destroy them at job end.
type Binding struct {
	job, hostname   string
	addresses       []netip.Addr
	permissions     []Permission
	limits          Limits
	issued, expires time.Time
}

func (b Binding) JobID() string             { return b.job }
func (b Binding) Hostname() string          { return b.hostname }
func (b Binding) Addresses() []netip.Addr   { return append([]netip.Addr(nil), b.addresses...) }
func (b Binding) Permissions() []Permission { return append([]Permission(nil), b.permissions...) }
func (b Binding) Limits() Limits            { return b.limits }
func (b Binding) ExpiresAt() time.Time      { return b.expires }
func (b Binding) ValidAt(now time.Time) bool {
	return b.job != "" && !now.IsZero() && !now.Before(b.issued) && now.Before(b.expires)
}

var jobID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var numericAddressLabel = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]+)$`)

func New(options Options, resolver Exchange) (*Binder, error) {
	if !jobID.MatchString(options.JobID) || options.JobID == "00000000-0000-0000-0000-000000000000" || len(options.SensitiveNetworks) == 0 || len(options.SensitiveNetworks) > 256 {
		return nil, ErrPolicy
	}
	for _, prefix := range options.SensitiveNetworks {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return nil, ErrPolicy
		}
	}
	if options.Mode == "none" {
		if len(options.Permissions) != 0 || options.Limits != (Limits{}) || options.MaximumTTL != 0 {
			return nil, ErrPolicy
		}
	} else if (options.Mode != "restricted" && options.Mode != "allowlist") || resolver == nil || len(options.Permissions) == 0 || len(options.Permissions) > 128 || options.Limits.Connections == 0 || options.Limits.BytesPerSecond == 0 || options.MaximumTTL < time.Second || options.MaximumTTL > 5*time.Minute {
		return nil, ErrPolicy
	}
	permissions := map[string][]Permission{}
	seen := map[Permission]bool{}
	for _, p := range options.Permissions {
		// Hosted workloads have no SMTP exception in this foundation. Controlled
		// DNS is the only resolver; arbitrary DNS/DoT ports are not grants.
		if !hostname(p.Hostname) || blockedPort(p.Port) || (p.Protocol != "tcp" && p.Protocol != "udp") || seen[p] {
			return nil, ErrPolicy
		}
		seen[p] = true
		permissions[p.Hostname] = append(permissions[p.Hostname], p)
	}
	for _, list := range permissions {
		sort.Slice(list, func(i, j int) bool {
			if list[i].Port != list[j].Port {
				return list[i].Port < list[j].Port
			}
			return list[i].Protocol < list[j].Protocol
		})
	}
	return &Binder{job: options.JobID, permissions: permissions, limits: options.Limits, sensitive: append([]netip.Prefix(nil), options.SensitiveNetworks...), maxTTL: options.MaximumTTL, resolver: resolver, slot: make(chan struct{}, 1), pins: map[string][32]byte{}, poisoned: map[string]bool{}, now: time.Now}, nil
}

// Resolve validates both address families before returning any addresses. A
// hostname's first complete public set is pinned for this job; a changed set
// permanently poisons that name for the job rather than silently moving traffic.
func (b *Binder) Resolve(ctx context.Context, name string) (Binding, error) {
	if b == nil || ctx == nil || !hostname(name) || len(b.permissions[name]) == 0 {
		return Binding{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case b.slot <- struct{}{}:
	case <-ctx.Done():
		return Binding{}, ErrDNS
	}
	defer func() { <-b.slot }()
	if b.poisoned[name] {
		return Binding{}, ErrRebinding
	}
	start := b.now()
	addresses, ttl, err := b.resolve(ctx, name)
	if err != nil {
		return Binding{}, err
	}
	if ctx.Err() != nil {
		return Binding{}, ErrDNS
	}
	expires := start.Add(min(ttl, b.maxTTL))
	if !b.now().Before(expires) {
		return Binding{}, ErrExpired
	}
	var canonical strings.Builder
	for _, addr := range addresses {
		canonical.WriteString(addr.String())
		canonical.WriteByte('\n')
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	if prior, exists := b.pins[name]; exists && prior != digest {
		b.poisoned[name] = true
		return Binding{}, ErrRebinding
	}
	b.pins[name] = digest
	return Binding{b.job, name, addresses, append([]Permission(nil), b.permissions[name]...), b.limits, start, expires}, nil
}

func blockedPort(port uint16) bool {
	return port == 0 || port == 25 || port == 465 || port == 587 || port == 53 || port == 853
}

func hostname(host string) bool {
	if len(host) == 0 || len(host) > 253 || host != strings.ToLower(host) || !strings.Contains(host, ".") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	letter, numeric := false, true
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		numeric = numeric && numericAddressLabel.MatchString(label)
		for _, c := range label {
			if c >= 'a' && c <= 'z' {
				letter = true
			} else if c != '-' && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return letter && !numeric
}
