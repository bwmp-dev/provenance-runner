//go:build linux

package controlchannel

import (
	"context"
	"time"
)

// RootObservationPacket can only be produced by receiving the dedicated kind
// from a kernel-authenticated root peer. JSON decoding and guest-result relay
// packets cannot populate it. It is a historical receipt, not live authority.
type RootObservationPacket struct {
	payload       []byte
	authenticated bool
}

func (p *RootObservationPacket) Payload() ([]byte, bool) {
	if p == nil || !p.authenticated {
		return nil, false
	}
	return append([]byte(nil), p.payload...), true
}

// ReceiveRootObservation is a fixed protocol phase. The root service must send
// this before relaying guest output, which always uses Result, never Observation.
// Any unexpected packet or descriptor closes the connection and transferred FDs.
func (c *Channel) ReceiveRootObservation(deadline time.Time) (*RootObservationPacket, error) {
	if c == nil {
		return nil, ErrChannel
	}
	if c.peer != 0 || !c.validPeer() {
		_ = c.Close()
		return nil, ErrChannel
	}
	packet, err := c.Receive(deadline)
	if err != nil {
		return nil, err
	}
	return c.rootObservationReceipt(packet)
}

func (c *Channel) rootObservationReceipt(packet Packet) (*RootObservationPacket, error) {
	if packet.Kind != Observation || len(packet.Files) != 0 || len(packet.Payload) == 0 || !c.validPeer() {
		for _, file := range packet.Files {
			_ = file.Close()
		}
		_ = c.Close()
		return nil, ErrChannel
	}
	return &RootObservationPacket{payload: append([]byte(nil), packet.Payload...), authenticated: true}, nil
}

// AwaitRootObservation permits only empty preparation keepalives before the
// dedicated observation. This does not renew the caller's preparation budget:
// an explicit deadline no more than one hour away is mandatory. Cancellation
// interrupts the owned socket. Unexpected phases and FDs close it permanently.
func (c *Channel) AwaitRootObservation(ctx context.Context) (*RootObservationPacket, error) {
	if c == nil || ctx == nil {
		return nil, ErrChannel
	}
	end, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || time.Until(end) <= 0 || time.Until(end) > time.Hour || c.peer != 0 || !c.validPeer() {
		_ = c.Close()
		return nil, ErrChannel
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	for progress := 0; progress <= 512; progress++ {
		deadline := time.Now().Add(25 * time.Second)
		if end.Before(deadline) {
			deadline = end
		}
		packet, err := c.Receive(deadline)
		if err != nil {
			return nil, err
		}
		if ctx.Err() != nil || !time.Now().Before(end) {
			for _, file := range packet.Files {
				_ = file.Close()
			}
			_ = c.Close()
			return nil, ErrChannel
		}
		if packet.Kind != Preparing {
			return c.rootObservationReceipt(packet)
		}
		if len(packet.Payload) != 0 || len(packet.Files) != 0 || ctx.Err() != nil {
			for _, file := range packet.Files {
				_ = file.Close()
			}
			_ = c.Close()
			return nil, ErrChannel
		}
	}
	_ = c.Close()
	return nil, ErrChannel
}
