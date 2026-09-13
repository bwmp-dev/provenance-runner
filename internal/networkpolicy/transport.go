package networkpolicy

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"time"
)

// TCPResolver uses only this operator-selected literal endpoint, never the OS
// resolver, search domains, environment proxies, fallback servers or redirects.
// Selecting/authenticating the resolver and isolating its network remain duties
// of the future privileged controller. This is not a DNS server for workloads.
type TCPResolver struct{ Endpoint netip.AddrPort }

func (r TCPResolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if ctx == nil || !r.Endpoint.IsValid() || r.Endpoint.Port() == 0 || r.Endpoint.Addr().Zone() != "" || r.Endpoint.Addr().Is4In6() || len(query) < 12 || len(query) > maxDNSBytes {
		return nil, ErrDNS
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", r.Endpoint.String())
	if err != nil {
		return nil, ErrDNS
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return nil, ErrDNS
	}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if _, err := io.Copy(connection, bytes.NewReader(frame)); err != nil {
		return nil, ErrDNS
	}
	var header [2]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return nil, ErrDNS
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size < 12 || size > maxDNSBytes {
		return nil, ErrDNS
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(connection, response); err != nil || ctx.Err() != nil {
		return nil, ErrDNS
	}
	return response, nil
}
