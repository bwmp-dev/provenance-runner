package networkpolicy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// These are unprivileged loopback transport tests, not namespace/firewall proof.
func serveDNSFixture(t *testing.T, peer string) (*WorkloadDNS, string, context.CancelFunc, <-chan error) {
	t.Helper()
	b := binder(t, responder(nil))
	binding, err := b.Resolve(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	view, err := NewWorkloadDNS(binding.JobID(), []Binding{binding}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeOwnedDNS(ctx, view, udp, tcp, []netip.Addr{netip.MustParseAddr(peer)}) }()
	t.Cleanup(func() { cancel(); _ = udp.Close(); _ = tcp.Close() })
	return view, tcp.Addr().String(), cancel, done
}

func TestOwnedDNSRealUDPAndTCPBoundedExchange(t *testing.T) {
	view, address, cancel, done := serveDNSFixture(t, "127.0.0.1")
	query := workloadQuery(t, "api.example.com", dnsmessage.TypeA)
	for _, transport := range []string{"udp4", "tcp4"} {
		connection, err := net.DialTimeout(transport, address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		frame := query
		if transport == "tcp4" {
			frame = make([]byte, 2+len(query))
			binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
			copy(frame[2:], query)
		}
		if _, err = connection.Write(frame); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 4096)
		var n int
		if transport == "tcp4" {
			var prefix [2]byte
			if _, err = io.ReadFull(connection, prefix[:]); err != nil {
				t.Fatal(err)
			}
			n = int(binary.BigEndian.Uint16(prefix[:]))
			if n > 4096 {
				t.Fatal("unbounded frame")
			}
			_, err = io.ReadFull(connection, buffer[:n])
		} else {
			n, err = connection.Read(buffer)
		}
		_ = connection.Close()
		if err != nil {
			t.Fatal(err)
		}
		var response dnsmessage.Message
		if response.Unpack(buffer[:n]) != nil || response.ID != 42 || response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 1 {
			t.Fatal("real transport response mismatch")
		}
	}
	// Cancellation closes a peer that has not finished its frame, then withdraws
	// the shared view; no transport goroutine may outlive the returned result.
	idle, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	_, _ = idle.Write([]byte{0})
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DNS transport did not stop")
	}
	answer, err := view.Answer(query, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var response dnsmessage.Message
	_ = response.Unpack(answer)
	if response.RCode != dnsmessage.RCodeServerFailure || len(response.Answers) != 0 {
		t.Fatal("cancelled listener retained DNS view")
	}
}

func TestOwnedDNSRejectsForeignPeersAndOversizedTCPBeforeBody(t *testing.T) {
	_, address, cancel, done := serveDNSFixture(t, "127.0.0.2")
	connection, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	_, _ = connection.Write([]byte{0xff, 0xff})
	var one [1]byte
	if _, err = connection.Read(one[:]); err == nil {
		t.Fatal("foreign peer received response")
	}
	_ = connection.Close()
	cancel()
	<-done
	_, address, cancel, done = serveDNSFixture(t, "127.0.0.1")
	connection, err = net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = connection.Write([]byte{0xff, 0xff})
	if _, err = connection.Read(one[:]); err == nil {
		t.Fatal("oversized frame accepted")
	}
	_ = connection.Close()
	cancel()
	<-done
}

func TestOwnedDNSOneGlobalResponseBudget(t *testing.T) {
	_, address, cancel, done := serveDNSFixture(t, "127.0.0.1")
	connection, err := net.DialTimeout("udp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	query := workloadQuery(t, "api.example.com", dnsmessage.TypeA)
	for range 70 {
		if _, err = connection.Write(query); err != nil {
			t.Fatal(err)
		}
	}
	_ = connection.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	count := 0
	var buffer [512]byte
	for {
		if _, err = connection.Read(buffer[:]); err != nil {
			break
		}
		count++
	}
	if count == 0 || count > 64 {
		t.Fatal("unbounded response budget", count)
	}
	cancel()
	<-done
}
