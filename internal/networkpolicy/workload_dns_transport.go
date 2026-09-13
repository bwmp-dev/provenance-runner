package networkpolicy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const workloadDNSDeadline = time.Second

// ServeOwnedDNS takes ownership of already-open job-namespace sockets. The
// trusted actuator must verify their namespace and firewall before calling it;
// this function never opens an ambient listener or infers isolation from an IP.
// Both sockets and all connections close on cancellation or either loop failing.
// Only exact trusted job peers are served. No request can select a resolver.
// On validation failure the caller retains ownership of its sockets.
func ServeOwnedDNS(ctx context.Context, view *WorkloadDNS, udp net.PacketConn, tcp net.Listener, peers []netip.Addr) error {
	if view == nil {
		return ErrPolicy
	}
	return serveOwnedDNS(ctx, view.Answer, view.Withdraw, udp, tcp, peers)
}

// ServeRouteDNS owns stable job-namespace sockets for the entire route session.
// Each request sees only the currently installed DNS view. Renewal does not
// rebind sockets or reset the shared transport budget. Socket failure or owner
// cancellation withdraws the route; route termination closes every DNS socket.
// Namespace/socket provenance is still the trusted caller's responsibility.
// Invalid socket inputs remain caller-owned, but still withdraw this route.
func ServeRouteDNS(ctx context.Context, session *RouteSession, udp net.PacketConn, tcp net.Listener, peers []netip.Addr) error {
	if ctx == nil || session == nil || session.ctx == nil || session.done == nil {
		return ErrPolicy
	}
	if _, err := session.DNS(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-session.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() { cancel(); <-watchDone }()
	var stopOnce sync.Once
	var withdrawal error
	stop := func() { stopOnce.Do(func() { withdrawal = session.Withdraw() }) }
	answer := func(query []byte, stream bool, now time.Time) ([]byte, error) {
		view, err := session.DNS()
		if err != nil {
			return nil, err
		}
		return view.Answer(query, stream, now)
	}
	err := serveOwnedDNS(ctx, answer, stop, udp, tcp, peers)
	stop()
	return errors.Join(err, withdrawal)
}

func serveOwnedDNS(ctx context.Context, answer func([]byte, bool, time.Time) ([]byte, error), withdraw func(), udp net.PacketConn, tcp net.Listener, peers []netip.Addr) error {
	if ctx == nil || udp == nil || tcp == nil || len(peers) == 0 || len(peers) > 2 {
		return ErrPolicy
	}
	u, err := netip.ParseAddrPort(udp.LocalAddr().String())
	if err != nil {
		return ErrPolicy
	}
	t, err := netip.ParseAddrPort(tcp.Addr().String())
	if err != nil || u != t || u.Port() == 0 || u.Addr().IsUnspecified() || u.Addr().Zone() != "" {
		return ErrPolicy
	}
	allowed := map[netip.Addr]bool{}
	for _, peer := range peers {
		if !peer.IsValid() || peer.Zone() != "" || peer.IsUnspecified() || peer.IsMulticast() || peer.Is4In6() || allowed[peer] {
			return ErrPolicy
		}
		allowed[peer] = true
	}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var activeMu sync.Mutex
	active := map[net.Conn]bool{}
	closeSockets := func() {
		_ = udp.Close()
		_ = tcp.Close()
		activeMu.Lock()
		for connection := range active {
			_ = connection.Close()
		}
		activeMu.Unlock()
		withdraw()
	}
	stop := context.AfterFunc(ctx, closeSockets)
	defer func() { stop(); closeSockets() }()
	peerAllowed := func(address net.Addr) bool {
		parsed, err := netip.ParseAddrPort(address.String())
		return err == nil && allowed[parsed.Addr().Unmap()]
	}
	var budgetMu sync.Mutex
	window := time.Now()
	requests := 0
	admit := func() bool {
		budgetMu.Lock()
		defer budgetMu.Unlock()
		now := time.Now()
		if now.Sub(window) >= time.Second {
			window = now
			requests = 0
		}
		if requests >= 64 {
			return false
		}
		requests++
		return true
	}
	errors := make(chan error, 2)
	var loops, connections sync.WaitGroup
	loops.Add(2)
	go func() {
		defer loops.Done()
		var buffer [513]byte
		for {
			n, peer, err := udp.ReadFrom(buffer[:])
			if err != nil {
				errors <- ErrDNS
				return
			}
			if n > 512 || !peerAllowed(peer) || !admit() {
				continue
			}
			response, err := answer(buffer[:n], false, time.Now())
			if err != nil {
				continue
			}
			if err = udp.SetWriteDeadline(time.Now().Add(workloadDNSDeadline)); err != nil {
				errors <- ErrDNS
				return
			}
			if _, err = udp.WriteTo(response, peer); err != nil {
				errors <- ErrDNS
				return
			}
		}
	}()
	go func() {
		defer loops.Done()
		for {
			connection, err := tcp.Accept()
			if err != nil {
				errors <- ErrDNS
				return
			}
			activeMu.Lock()
			if ctx.Err() != nil || len(active) >= 8 || !peerAllowed(connection.RemoteAddr()) || !admit() {
				activeMu.Unlock()
				_ = connection.Close()
				continue
			}
			active[connection] = true
			activeMu.Unlock()
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer func() { _ = connection.Close(); activeMu.Lock(); delete(active, connection); activeMu.Unlock() }()
				if connection.SetDeadline(time.Now().Add(workloadDNSDeadline)) != nil {
					return
				}
				var prefix [2]byte
				if _, err := io.ReadFull(connection, prefix[:]); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(prefix[:]))
				if size < 12 || size > 512 {
					return
				}
				var body [512]byte
				if _, err := io.ReadFull(connection, body[:size]); err != nil {
					return
				}
				answer, err := answer(body[:size], true, time.Now())
				if err != nil {
					return
				}
				binary.BigEndian.PutUint16(prefix[:], uint16(len(answer)))
				frame := make([]byte, 2+len(answer))
				copy(frame, prefix[:])
				copy(frame[2:], answer)
				_, _ = io.Copy(connection, bytes.NewReader(frame))
			}()
		}
	}()
	failed := false
	select {
	case <-ctx.Done():
	case <-errors:
		// Preserve an initiating socket failure even when withdrawing the route
		// subsequently cancels the supervision context during cleanup.
		failed = parent.Err() == nil
		cancel()
	}
	closeSockets()
	loops.Wait()
	connections.Wait()
	if failed {
		return ErrDNS
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	return ErrDNS
}
