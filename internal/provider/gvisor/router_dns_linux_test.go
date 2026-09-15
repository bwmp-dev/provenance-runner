//go:build linux

package gvisor

import (
	"golang.org/x/sys/unix"
	"os"
	"syscall"
	"testing"
)

func TestRouterDNSRequiresOwnedSockets(t *testing.T) {
	if sendRouterDNS(-1) {
		t.Fatal("invalid transfer channel admitted")
	}
	if d, err := receiveRouterDNS(-1, nil, "foreign"); d != nil || err == nil {
		t.Fatal("missing socket owner admitted")
	}
	for _, d := range []*routerDNS{nil, {}} {
		if d.validate() == nil || d.Close() != nil || d.Close() != nil {
			t.Fatal("empty DNS owner handling")
		}
	}
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if validRouterDNSSocket(int(file.Fd()), false, unix.Stat_t{}) {
		t.Fatal("regular descriptor accepted as DNS")
	}
}

func assertRouterDNSOrigin(t *testing.T, owner *RouterOwner) {
	t.Helper()
	if owner.dns.validate() != nil {
		t.Fatal("actual owned DNS sockets unavailable")
	}
	parent, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal("parent namespace observation")
	}
	defer parent.Close()
	var host unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &host) != nil {
		t.Fatal("parent namespace identity")
	}
	for i, socket := range []interface {
		SyscallConn() (syscall.RawConn, error)
	}{owner.dns.udp, owner.dns.tcp} {
		raw, err := socket.SyscallConn()
		if err != nil {
			t.Fatal("retained DNS descriptor")
		}
		wrongNetwork, wrongProtocol, actual := false, false, false
		if raw.Control(func(fd uintptr) {
			actual = validRouterDNSSocket(int(fd), i == 1, owner.dns.network)
			wrongNetwork = validRouterDNSSocket(int(fd), i == 1, host)
			wrongProtocol = validRouterDNSSocket(int(fd), i != 1, owner.dns.network)
		}) != nil || !actual || wrongNetwork || wrongProtocol {
			t.Fatal("DNS socket provenance or transport confusion")
		}
	}
}
