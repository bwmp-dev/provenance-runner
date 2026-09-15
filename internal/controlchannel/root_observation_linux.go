//go:build linux

package controlchannel

import "time"

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
	if packet.Kind != Observation || len(packet.Files) != 0 || len(packet.Payload) == 0 || !c.validPeer() {
		for _, file := range packet.Files {
			_ = file.Close()
		}
		_ = c.Close()
		return nil, ErrChannel
	}
	return &RootObservationPacket{payload: append([]byte(nil), packet.Payload...), authenticated: true}, nil
}
