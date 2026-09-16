//go:build linux

package controlchannel

import (
	"encoding/binary"
	"errors"
	"os"
	"time"
)

const MaximumStartBytes = 2 << 20
const MaximumStartFiles = 256

// StartRequest is transport ownership, not execution authorization. The root
// dispatcher must decode its closed schema and independently derive file roles,
// sizes and hashes. A successful receiver owns Files and must close them.
type StartRequest struct {
	Payload      []byte
	Files        []*os.File
	LastSequence uint64
	// IdleNonce is set only by ReceiveServiceRequest for a standalone probe.
	// It never accompanies execution payloads or input files.
	IdleNonce []byte
	// SecretNonce is a separate explicit capability probe, never an execution.
	SecretNonce  []byte
	MaximumNonce []byte
}

// SendStart sends the first request on a fresh authenticated channel. One shared
// deadline bounds the whole assembly; chunking cannot renew it. Files remain
// borrowed. The returned sequence precedes subsequent control messages.
func SendStart(channel *Channel, payload []byte, files []*os.File, deadline time.Time) (last uint64, result error) {
	if channel == nil {
		return 0, ErrChannel
	}
	defer func() {
		if result != nil {
			_ = channel.Close()
		}
	}()
	if !validDeadline(deadline) || len(payload) < 1 || len(payload) > MaximumStartBytes || len(files) < 1 || len(files) > MaximumStartFiles {
		return 0, ErrChannel
	}
	header := make([]byte, 12)
	copy(header, "PVS1")
	binary.BigEndian.PutUint32(header[4:8], uint32(len(payload)))
	binary.BigEndian.PutUint16(header[8:10], uint16(len(files)))
	send := func(data []byte, fds []*os.File) error {
		last++
		return channel.Send(Packet{Kind: Start, Sequence: last, Payload: data, Files: fds}, deadline)
	}
	if err := send(header, nil); err != nil {
		return last, err
	}
	for offset := 0; offset < len(payload); {
		end := min(offset+MaximumPayload, len(payload))
		if err := send(payload[offset:end], nil); err != nil {
			return last, err
		}
		offset = end
	}
	for offset := 0; offset < len(files); {
		end := min(offset+MaximumFiles, len(files))
		if err := send(nil, files[offset:end]); err != nil {
			return last, err
		}
		offset = end
	}
	return last, nil
}

// ReceiveStart owns and closes every received descriptor on refusal. It accepts
// exact full-size chunks followed by exact file batches, with no repeated header,
// interleaved control messages or per-chunk deadline extension. The channel is
// permanently closed on any malformed or incomplete request.
func ReceiveStart(channel *Channel, deadline time.Time) (accepted *StartRequest, result error) {
	return receiveStart(channel, deadline, false)
}

// ReceiveServiceRequest additionally accepts a standalone bounded idle probe.
// It provides no job authorization and cannot be followed by a Start request on
// this channel. The root service must check its actual controller before reply.
func ReceiveServiceRequest(channel *Channel, deadline time.Time) (*StartRequest, error) {
	return receiveStart(channel, deadline, true)
}

func receiveStart(channel *Channel, deadline time.Time, allowIdle bool) (accepted *StartRequest, result error) {
	if channel == nil {
		return nil, ErrChannel
	}
	r := &StartRequest{}
	defer func() {
		if result != nil {
			for _, file := range r.Files {
				_ = file.Close()
			}
			_ = channel.Close()
		}
	}()
	receive := func() (Packet, error) {
		packet, err := channel.Receive(deadline)
		// Receive owns successful packet FDs even when the application envelope
		// is wrong. Retain them before validating kind/position, so refusal closes.
		if err == nil {
			r.Files = append(r.Files, packet.Files...)
		}
		if err != nil {
			return Packet{}, err
		}
		r.LastSequence++
		if (packet.Kind != Start && !(allowIdle && r.LastSequence == 1 && (packet.Kind == IdleCheck || packet.Kind == SecretCheck || packet.Kind == MaximumCheck))) || packet.Sequence != r.LastSequence {
			return Packet{}, ErrChannel
		}
		return packet, nil
	}
	header, err := receive()
	if err == nil && (header.Kind == IdleCheck || header.Kind == SecretCheck || header.Kind == MaximumCheck) {
		if len(header.Payload) != 32 || len(header.Files) != 0 {
			return nil, ErrChannel
		}
		if header.Kind == MaximumCheck {
			r.MaximumNonce = append([]byte(nil), header.Payload...)
		} else if header.Kind == SecretCheck {
			r.SecretNonce = append([]byte(nil), header.Payload...)
		} else {
			r.IdleNonce = append([]byte(nil), header.Payload...)
		}
		return r, nil
	}
	if err != nil || len(header.Payload) != 12 || len(header.Files) != 0 {
		return nil, errors.Join(ErrChannel, err)
	}
	raw := header.Payload
	if string(raw[:4]) != "PVS1" || raw[10] != 0 || raw[11] != 0 {
		return nil, ErrChannel
	}
	length, count := int(binary.BigEndian.Uint32(raw[4:8])), int(binary.BigEndian.Uint16(raw[8:10]))
	if length < 1 || length > MaximumStartBytes || count < 1 || count > MaximumStartFiles {
		return nil, ErrChannel
	}
	r.Payload = make([]byte, 0, length)
	for len(r.Payload) < length {
		packet, err := receive()
		if err != nil || len(packet.Files) != 0 || len(packet.Payload) != min(MaximumPayload, length-len(r.Payload)) {
			return nil, errors.Join(ErrChannel, err)
		}
		r.Payload = append(r.Payload, packet.Payload...)
	}
	for len(r.Files) < count {
		remaining := count - len(r.Files)
		packet, err := receive()
		if err != nil || len(packet.Payload) != 0 || len(packet.Files) != min(MaximumFiles, remaining) {
			return nil, errors.Join(ErrChannel, err)
		}
	}
	return r, nil
}
