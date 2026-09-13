package networkpolicy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// These exercise real loopback transports with a recording actuator, not
// namespace ownership or measured runtime. Disposable Sentry CI covers routing.
func TestRouteDNSStableSocketsAndBidirectionalShutdown(t *testing.T) {
	for _, mode := range []string{"owner-cancel", "udp-failure", "tcp-failure", "route-withdraw", "route-expiry", "cleanup-failure"} {
		t.Run(mode, func(t *testing.T) {
			binding := liveRouteBinding(t)
			route := &recordingRoute{}
			session, err := StartRoute(context.Background(), binding.job, []Binding{binding}, route)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				route.mu.Lock()
				route.failApply = false
				route.failDisconnect = false
				route.mu.Unlock()
				if err := session.Close(); err != nil {
					t.Error(err)
				}
			})
			tcp, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			udp, err := net.ListenPacket("udp4", tcp.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- ServeRouteDNS(ctx, session, udp, tcp, []netip.Addr{netip.MustParseAddr("127.0.0.1")}) }()
			peer, err := net.Dial("udp4", tcp.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			query := workloadQuery(t, "api.example.com", dnsmessage.TypeA)
			ask := func(stream bool) {
				t.Helper()
				connection := peer
				frame := query
				if stream {
					connection, err = net.DialTimeout("tcp4", tcp.Addr().String(), time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer connection.Close()
					frame = make([]byte, 2+len(query))
					binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
					copy(frame[2:], query)
				}
				_ = connection.SetDeadline(time.Now().Add(time.Second))
				if _, err := connection.Write(frame); err != nil {
					t.Fatal(err)
				}
				var buffer [512]byte
				var n int
				if stream {
					var prefix [2]byte
					if _, err := io.ReadFull(connection, prefix[:]); err != nil {
						t.Fatal(err)
					}
					n = int(binary.BigEndian.Uint16(prefix[:]))
					if n > len(buffer) {
						t.Fatal("unbounded DNS frame")
					}
					_, err = io.ReadFull(connection, buffer[:n])
				} else {
					n, err = connection.Read(buffer[:])
				}
				if err != nil {
					t.Fatal(err)
				}
				var reply dnsmessage.Message
				if reply.Unpack(buffer[:n]) != nil || reply.RCode != dnsmessage.RCodeSuccess || len(reply.Answers) != 1 {
					t.Fatal("installed DNS view unavailable")
				}
			}
			ask(false)
			ask(true)
			old, err := session.DNS()
			if err != nil {
				t.Fatal(err)
			}
			binding.expires = binding.expires.Add(time.Second)
			if err := session.Refresh(ctx, []Binding{binding}); err != nil {
				t.Fatal(err)
			}
			if routeDNSAnswers(t, old) != 0 {
				t.Fatal("old view remains usable")
			}
			// Same UDP socket and same listeners survive the view replacement.
			ask(false)
			ask(true)
			switch mode {
			case "owner-cancel":
				cancel()
			case "udp-failure":
				_ = udp.Close()
			case "tcp-failure":
				_ = tcp.Close()
			case "route-withdraw":
				if err := session.Withdraw(); err != nil {
					t.Fatal(err)
				}
			case "route-expiry":
				// Accelerate only the userspace watcher in this recording-actuator
				// test; real kernel deadline enforcement has separate acceptance.
				session.mu.Lock()
				session.rules.expires = time.Now().Add(20 * time.Millisecond)
				session.mu.Unlock()
				select {
				case session.wake <- struct{}{}:
				default:
				}
			case "cleanup-failure":
				route.mu.Lock()
				route.failApply = true
				route.failDisconnect = true
				route.mu.Unlock()
				_ = udp.Close()
			}
			select {
			case err := <-done:
				if mode == "cleanup-failure" && !errors.Is(err, ErrActuation) {
					t.Fatal("cleanup failure hidden", err)
				}
				if mode == "udp-failure" || mode == "tcp-failure" {
					if !errors.Is(err, ErrDNS) {
						t.Fatal(err)
					}
				}
				if mode == "owner-cancel" || mode == "route-withdraw" || mode == "route-expiry" {
					if !errors.Is(err, context.Canceled) {
						t.Fatal("route termination was not reported", err)
					}
				}
			case <-time.After(10 * time.Second):
				t.Fatal("route DNS supervision did not stop")
			}
			if _, err := session.DNS(); err != ErrExpired {
				t.Fatal("DNS failure left a live route view")
			}
			if !slices.Contains(route.records(), "disconnect") {
				t.Fatal("route disconnection not attempted")
			}
			if udp.SetReadDeadline(time.Now()) == nil {
				t.Fatal("UDP listener remains open")
			}
			_ = tcp.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
			if connection, err := tcp.Accept(); !errors.Is(err, net.ErrClosed) {
				if connection != nil {
					_ = connection.Close()
				}
				t.Fatal("TCP listener remains open")
			}
		})
	}
}

func TestRouteDNSInvalidSocketsRemainCallerOwnedButWithdrawRoute(t *testing.T) {
	binding := liveRouteBinding(t)
	session, err := StartRoute(context.Background(), binding.job, []Binding{binding}, &recordingRoute{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if err := ServeRouteDNS(context.Background(), session, udp, nil, nil); !errors.Is(err, ErrPolicy) {
		t.Fatal(err)
	}
	if udp.SetReadDeadline(time.Now()) != nil {
		t.Fatal("invalid sockets transferred ownership")
	}
	if _, err := session.DNS(); err != ErrExpired {
		t.Fatal("invalid server setup left route active")
	}
}
