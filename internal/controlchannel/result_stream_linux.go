//go:build linux

package controlchannel

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// Bounds include the guest protocol's 16 MiB logs, 4 MiB events and frame
// headers. Packet count also bounds empty keepalives and fragmented streams.
const MaximumResultBytes = 21 << 20
const MaximumResultPackets = 32768

// RootCompletion is a historical receipt from the privileged owner, not a
// guest outcome. The service may send Completion only after successful owned
// cleanup and collection of the actual kernel process exit. Infrastructure
// failures remain failures even if the guest exited zero.
type RootCompletion struct {
	exit                 int
	infra, authenticated bool
}

func (r *RootCompletion) Outcome() (int, bool, error) {
	if r == nil || !r.authenticated {
		return 0, true, ErrChannel
	}
	return r.exit, r.infra, nil
}

// EncodeCompletion is only serialization, not proof. The worker accepts this
// payload exclusively from an authenticated root peer under Completion.
func EncodeCompletion(exit int, infrastructureFailure bool) ([]byte, error) {
	if exit < 0 || exit > 255 {
		return nil, ErrChannel
	}
	flag := byte(0)
	if infrastructureFailure {
		flag = 1
	}
	return []byte{'P', 'V', 'C', 'R', 1, byte(exit), flag, 0}, nil
}

// ResultStream consumes the fixed phase AFTER ReceiveRootObservation. Guest
// bytes always use Result; only root retirement uses Completion. Socket EOF
// without completion is an infrastructure error, never successful guest EOF.
// Empty Result packets are bounded keepalives during quiet execution. The root
// must send one at least every 20 seconds until completion.
// Read and Receipt are single-consumer; Close may be called concurrently.
type ResultStream struct {
	channel        *Channel
	ctx            context.Context
	stop           func() bool
	closeOnce      sync.Once
	pending        []byte
	bytes, packets int
	receipt        *RootCompletion
	err            error
}

func NewResultStream(ctx context.Context, channel *Channel) (*ResultStream, error) {
	if ctx == nil || ctx.Err() != nil || channel == nil || channel.peer != 0 || !channel.validPeer() {
		return nil, ErrChannel
	}
	r := &ResultStream{channel: channel, ctx: ctx}
	r.stop = context.AfterFunc(ctx, func() { _ = channel.Close() })
	return r, nil
}

func (r *ResultStream) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.stop != nil {
			r.stop()
		}
		_ = r.channel.Close()
	})
	return nil
}

func (r *ResultStream) Receipt() (*RootCompletion, error) {
	if r == nil || r.ctx == nil || r.err != nil || r.receipt == nil || r.ctx.Err() != nil {
		return nil, ErrChannel
	}
	copy := *r.receipt
	return &copy, nil
}

func (r *ResultStream) fail(err error) (int, error) {
	r.err = errors.Join(ErrChannel, err)
	r.pending = nil
	r.receipt = nil
	_ = r.Close()
	return 0, r.err
}

func (r *ResultStream) Read(dst []byte) (int, error) {
	if r == nil || r.ctx == nil || r.channel == nil {
		return 0, ErrChannel
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.ctx.Err() != nil {
		return r.fail(r.ctx.Err())
	}
	if len(dst) == 0 {
		return 0, nil
	}
	for len(r.pending) == 0 {
		if r.receipt != nil {
			return 0, io.EOF
		}
		deadline := time.Now().Add(25 * time.Second)
		if end, ok := r.ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		packet, err := r.channel.Receive(deadline)
		if err != nil {
			return r.fail(err)
		}
		if len(packet.Files) != 0 {
			for _, file := range packet.Files {
				_ = file.Close()
			}
			return r.fail(ErrChannel)
		}
		r.packets++
		if r.packets > MaximumResultPackets {
			return r.fail(ErrChannel)
		}
		switch packet.Kind {
		case Result:
			if len(packet.Payload) > MaximumResultBytes-r.bytes {
				return r.fail(ErrChannel)
			}
			r.bytes += len(packet.Payload)
			r.pending = packet.Payload
		case Completion:
			p := packet.Payload
			if len(p) != 8 || string(p[:4]) != "PVCR" || p[4] != 1 || p[6] > 1 || p[7] != 0 {
				return r.fail(ErrChannel)
			}
			r.receipt = &RootCompletion{exit: int(p[5]), infra: p[6] == 1, authenticated: true}
			_ = r.Close()
		default:
			return r.fail(ErrChannel)
		}
	}
	n := copy(dst, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
