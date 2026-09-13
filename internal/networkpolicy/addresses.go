package networkpolicy

import "net/netip"

// Conservative special-purpose exclusions, based on the IANA IPv4/IPv6 special
// registries. Some registered special-purpose public ranges are intentionally
// excluded too; this foundation does not provide per-job exceptions.
var special = prefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32",
	"2002::/16", "2620:4f:8000::/48", "3fff::/20",
)
var globalIPv6 = netip.MustParsePrefix("2000::/3")

func prefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(values))
	for i, v := range values {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

func (b *Binder) public(addr netip.Addr) bool {
	// Reject mapped/translated representations, rather than normalizing them
	// into an alternate grant. IPv6 outside allocated global unicast is denied.
	if !addr.IsValid() || addr.Zone() != "" || addr.Is4In6() || !addr.IsGlobalUnicast() || addr.IsPrivate() || (addr.Is6() && !globalIPv6.Contains(addr)) {
		return false
	}
	for _, p := range special {
		if p.Contains(addr) {
			return false
		}
	}
	for _, p := range b.sensitive {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}
