package networkpolicy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Owns only a loopback ephemeral-port fixture, never upstream or host policy.
func tcpFixture(t *testing.T, answer func(net.Conn, []byte)) TCPResolver {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				var h [2]byte
				if _, err := io.ReadFull(c, h[:]); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(h[:]))
				if size > maxDNSBytes {
					return
				}
				q := make([]byte, size)
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				answer(c, q)
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; connections.Wait() })
	return TCPResolver{Endpoint: netip.MustParseAddrPort(listener.Addr().String())}
}

func TestControlledTCPTransportBothFamilies(t *testing.T) {
	resolver := tcpFixture(t, func(c net.Conn, q []byte) {
		raw, err := responder(nil).Exchange(context.Background(), q)
		if err != nil {
			return
		}
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], uint16(len(raw)))
		_, _ = c.Write(h[:1])
		_, _ = c.Write(h[1:])
		_, _ = c.Write(raw)
	})
	b := binder(t, resolver)
	got, err := b.Resolve(context.Background(), "api.example.com")
	if err != nil || len(got.Addresses()) != 2 || !got.ValidAt(time.Now()) {
		t.Fatal("real framed TCP resolution failed", err)
	}
}

func TestControlledTCPTransportBoundsAndCancellation(t *testing.T) {
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsName("api.example.com"), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for name, handler := range map[string]func(net.Conn, []byte){
		"oversized frame": func(c net.Conn, _ []byte) { _, _ = c.Write([]byte{0x10, 0x01}) },
		"zero frame":      func(c net.Conn, _ []byte) { _, _ = c.Write([]byte{0, 0}) },
		"partial header":  func(c net.Conn, _ []byte) { _, _ = c.Write([]byte{0}) },
		"partial body":    func(c net.Conn, _ []byte) { _, _ = c.Write([]byte{0, 12, 0}) },
	} {
		t.Run(name, func(t *testing.T) {
			r := tcpFixture(t, handler)
			if _, err := r.Exchange(context.Background(), raw); !errors.Is(err, ErrDNS) {
				t.Fatal(err)
			}
		})
	}
	r := tcpFixture(t, func(c net.Conn, _ []byte) { var v [1]byte; _, _ = c.Read(v[:]) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := r.Exchange(ctx, raw); !errors.Is(err, ErrDNS) || time.Since(started) > time.Second {
		t.Fatal("context did not bound resolver", err)
	}
	for _, endpoint := range []netip.AddrPort{{}, netip.MustParseAddrPort("127.0.0.1:0"), netip.MustParseAddrPort("[::ffff:127.0.0.1]:53"), netip.MustParseAddrPort("[fe80::1%lo]:53")} {
		if _, err := (TCPResolver{Endpoint: endpoint}).Exchange(context.Background(), raw); !errors.Is(err, ErrDNS) {
			t.Fatal("invalid endpoint admitted")
		}
	}
	if _, err := r.Exchange(nil, raw); !errors.Is(err, ErrDNS) {
		t.Fatal("nil context")
	}
	if _, err := r.Exchange(context.Background(), make([]byte, maxDNSBytes+1)); !errors.Is(err, ErrDNS) {
		t.Fatal("oversized query")
	}
}

func FuzzDNSResponse(f *testing.F) {
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsName("api.example.com"), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	raw, _ := q.Pack()
	valid, _ := responder(nil).Exchange(context.Background(), raw)
	f.Add(valid)
	f.Add(append(append([]byte(nil), valid...), 0))
	f.Add([]byte{0, 7, 128, 0, 255, 255, 255, 255, 255, 255, 255, 255})
	b, err := New(options(), responder(nil))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		addresses, ttl, err := b.parse(q, input)
		if err != nil {
			if len(addresses) != 0 || ttl != 0 {
				t.Fatal("partial binding on parser error")
			}
			return
		}
		if ttl <= 0 || ttl > options().MaximumTTL || len(addresses) > 64 {
			t.Fatal("unbounded parsed binding")
		}
		for _, address := range addresses {
			if !b.public(address) || !address.Is4() {
				t.Fatal("forbidden or wrong-family address escaped")
			}
		}
	})
}
