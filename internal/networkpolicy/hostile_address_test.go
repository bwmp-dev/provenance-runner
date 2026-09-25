package networkpolicy

import (
	"net/netip"
	"testing"
)

// WP-11C SSRF boundary: no resolved destination may be treated as a public,
// grantable address when it reaches cloud metadata, loopback, private
// management networks (PostgreSQL 5432 / Temporal 7233 hosts, the Coolify
// management host) or an alternate encoding of any of those.
var hostileDestinations = []string{
	"169.254.169.254", "169.254.170.2", "fd00:ec2::254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe",
	"2002:a9fe:a9fe::1", "127.0.0.1", "127.1.2.3", "::1", "0.0.0.0", "::", "255.255.255.255",
	"10.0.0.5", "10.255.255.254", "172.16.0.10", "172.31.255.1", "192.168.1.10", "100.64.0.1", "100.100.100.100",
	"fc00::1", "fd12:3456:789a::1", "fe80::1", "224.0.0.1", "ff02::1", "198.18.0.1", "192.0.2.1", "::ffff:10.0.0.5",
	"::ffff:127.0.0.1", "2001:db8::1",
}

func TestBinderNeverTreatsManagementOrMetadataAddressesAsPublic(t *testing.T) {
	binder := &Binder{}
	for _, value := range hostileDestinations {
		addr := netip.MustParseAddr(value)
		if binder.public(addr) {
			t.Errorf("%s classified as public", value)
		}
	}
	zoned := netip.MustParseAddr("fe80::1%eth0")
	if binder.public(zoned) {
		t.Error("zoned link-local classified as public")
	}
	operator := &Binder{sensitive: []netip.Prefix{netip.MustParsePrefix("203.0.114.0/24")}}
	if operator.public(netip.MustParseAddr("203.0.114.7")) {
		t.Error("operator-sensitive management prefix classified as public")
	}
	if !binder.public(netip.MustParseAddr("1.1.1.1")) || !binder.public(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Error("ordinary global unicast refused; the test oracle is broken")
	}
}

// FuzzBinderPublicAddress asserts the classifier never admits an address
// inside a well-known non-public range, whatever its byte encoding.
func FuzzBinderPublicAddress(f *testing.F) {
	for _, value := range hostileDestinations {
		addr := netip.MustParseAddr(value)
		bytes := addr.As16()
		f.Add(bytes[:])
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var addr netip.Addr
		switch len(raw) {
		case 4:
			addr = netip.AddrFrom4([4]byte(raw))
		case 16:
			addr = netip.AddrFrom16([16]byte(raw))
		default:
			return
		}
		if !(&Binder{}).public(addr) {
			return
		}
		unmapped := addr.Unmap()
		if unmapped.IsLoopback() || unmapped.IsPrivate() || unmapped.IsLinkLocalUnicast() || unmapped.IsMulticast() || unmapped.IsUnspecified() || unmapped.IsInterfaceLocalMulticast() {
			t.Fatalf("%s admitted as public", addr)
		}
		for _, prefix := range special {
			if prefix.Contains(unmapped) {
				t.Fatalf("%s admitted despite special prefix %s", addr, prefix)
			}
		}
	})
}
