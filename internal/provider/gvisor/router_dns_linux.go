//go:build linux

package gvisor

import (
	"errors"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"sync"
)

// sendRouterDNS runs only after the closed child has proved its fresh mapped
// namespace. The fixed address is not assigned until private-link preparation;
// FREEBIND avoids an ambient wildcard listener or a parent-thread setns.
func sendRouterDNS(channel int) bool {
	for option, want := range map[int]int{unix.SO_DOMAIN: unix.AF_UNIX, unix.SO_TYPE: unix.SOCK_SEQPACKET} {
		if got, err := unix.GetsockoptInt(channel, unix.SOL_SOCKET, option); err != nil || got != want {
			return false
		}
	}
	var sockets []int
	defer func() {
		for _, fd := range sockets {
			unix.Close(fd)
		}
	}()
	for _, kind := range []int{unix.SOCK_DGRAM, unix.SOCK_STREAM} {
		fd, err := unix.Socket(unix.AF_INET, kind|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			return false
		}
		sockets = append(sockets, fd)
		if unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_FREEBIND, 1) != nil || unix.Bind(fd, &unix.SockaddrInet4{Port: 53, Addr: [4]byte{10, 0, 1, 1}}) != nil {
			return false
		}
		if kind == unix.SOCK_STREAM && unix.Listen(fd, 16) != nil {
			return false
		}
	}
	n, err := unix.SendmsgN(channel, []byte{'d'}, unix.UnixRights(sockets...), nil, unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT)
	return err == nil && n == 1
}

type routerDNS struct {
	mu             sync.Mutex
	udp            *net.UDPConn
	tcp            *net.TCPListener
	child          *np.ChildNamespaces
	job            string
	network        unix.Stat_t
	closed, failed bool
	closeErr       error
}

// Every received descriptor is inspected and closed on refusal. SIOCGSKNS
// returns the actual socket network namespace, not a name supplied by a child.
func receiveRouterDNS(channel int, child *np.ChildNamespaces, job string) (*routerDNS, error) {
	if child == nil || child.Validate(job) != nil {
		return nil, ErrRouterOwner
	}
	var data [2]byte
	control := make([]byte, unix.CmsgSpace(2*4))
	n, size, flags, _, err := unix.Recvmsg(channel, data[:], control, unix.MSG_CMSG_CLOEXEC|unix.MSG_DONTWAIT)
	if err != nil {
		return nil, ErrRouterOwner
	}
	messages, parseErr := unix.ParseSocketControlMessage(control[:size])
	var received []int
	defer func() {
		for _, fd := range received {
			unix.Close(fd)
		}
	}()
	valid := parseErr == nil && len(messages) == 1
	for _, message := range messages {
		fds, err := unix.ParseUnixRights(&message)
		if err != nil {
			valid = false
		} else {
			received = append(received, fds...)
		}
	}
	if !valid || n != 1 || data[0] != 'd' || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(received) != 2 {
		return nil, ErrRouterOwner
	}
	network, err := child.NetworkForJob(job)
	if err != nil {
		return nil, ErrRouterOwner
	}
	defer network.Close()
	d := &routerDNS{child: child, job: job}
	if unix.Fstat(int(network.Fd()), &d.network) != nil || !validRouterDNSSocket(received[0], false, d.network) || !validRouterDNSSocket(received[1], true, d.network) {
		return nil, ErrRouterOwner
	}
	// net.File* duplicates descriptors. Keep original wrappers owned until the
	// conversion has completed; never let a finalizer close a reused raw number.
	udpFile, tcpFile := os.NewFile(uintptr(received[0]), "router-dns-udp"), os.NewFile(uintptr(received[1]), "router-dns-tcp")
	received = nil
	defer udpFile.Close()
	defer tcpFile.Close()
	udp, err := net.FilePacketConn(udpFile)
	if err != nil {
		return nil, ErrRouterOwner
	}
	u, ok := udp.(*net.UDPConn)
	if !ok {
		udp.Close()
		return nil, ErrRouterOwner
	}
	d.udp = u
	tcp, err := net.FileListener(tcpFile)
	if err != nil {
		d.Close()
		return nil, ErrRouterOwner
	}
	t, ok := tcp.(*net.TCPListener)
	if !ok {
		tcp.Close()
		d.Close()
		return nil, ErrRouterOwner
	}
	d.tcp = t
	if d.validate() != nil {
		d.Close()
		return nil, ErrRouterOwner
	}
	return d, nil
}

func validRouterDNSSocket(fd int, tcp bool, network unix.Stat_t) bool {
	kind, protocol, accepting := unix.SOCK_DGRAM, unix.IPPROTO_UDP, 0
	if tcp {
		kind, protocol, accepting = unix.SOCK_STREAM, unix.IPPROTO_TCP, 1
	}
	for option, want := range map[int]int{unix.SO_DOMAIN: unix.AF_INET, unix.SO_TYPE: kind, unix.SO_PROTOCOL: protocol, unix.SO_ACCEPTCONN: accepting} {
		if got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, option); err != nil || got != want {
			return false
		}
	}
	address, err := unix.Getsockname(fd)
	v4, ok := address.(*unix.SockaddrInet4)
	if err != nil || !ok || v4.Port != 53 || v4.Addr != [4]byte{10, 0, 1, 1} {
		return false
	}
	namespace, err := unix.IoctlRetInt(fd, unix.SIOCGSKNS)
	if err != nil {
		return false
	}
	defer unix.Close(namespace)
	var actual unix.Stat_t
	return unix.Fstat(namespace, &actual) == nil && actual.Dev == network.Dev && actual.Ino == network.Ino
}

func (d *routerDNS) validate() error {
	if d == nil {
		return ErrRouterOwner
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.failed || d.child == nil || d.udp == nil || d.tcp == nil || d.child.Validate(d.job) != nil {
		d.failed = true
		return ErrRouterOwner
	}
	udp, err := d.udp.SyscallConn()
	if err != nil {
		d.failed = true
		return ErrRouterOwner
	}
	tcp, err := d.tcp.SyscallConn()
	if err != nil {
		d.failed = true
		return ErrRouterOwner
	}
	for i, connection := range []interface{ Control(func(uintptr)) error }{udp, tcp} {
		valid := false
		if connection.Control(func(fd uintptr) { valid = validRouterDNSSocket(int(fd), i == 1, d.network) }) != nil || !valid {
			d.failed = true
			return ErrRouterOwner
		}
	}
	return nil
}

func (d *routerDNS) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return d.closeErr
	}
	d.closed = true
	var result error
	if d.udp != nil {
		if err := d.udp.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	if d.tcp != nil {
		if err := d.tcp.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	d.closeErr = result
	return d.closeErr
}
