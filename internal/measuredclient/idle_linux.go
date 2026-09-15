//go:build linux

package measuredclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
)

// CheckIdle owns a fresh root channel. Success is a momentary controller
// capacity barrier after failed-session teardown, not a job outcome, retirement
// receipt for publication, or permission to resume expired authority. Callers
// must first stop and join their prior session and serialize local admission.
func CheckIdle(ctx context.Context, channel *cc.Channel) error {
	if channel == nil {
		return ErrSession
	}
	defer channel.Close()
	peer, err := channel.PeerUID()
	if ctx == nil || ctx.Err() != nil || err != nil || peer != 0 {
		return ErrSession
	}
	stop := context.AfterFunc(ctx, func() { channel.Close() })
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil || channel.Send(cc.Packet{Kind: cc.IdleCheck, Sequence: 1, Payload: nonce}, deadline) != nil {
		return ErrSession
	}
	packet, err := channel.Receive(deadline)
	for _, file := range packet.Files {
		_ = file.Close()
	}
	if err != nil || ctx.Err() != nil || len(packet.Files) != 0 || packet.Kind != cc.IdleConfirmed || packet.Sequence != 1 || !bytes.Equal(packet.Payload, nonce) {
		return ErrSession
	}
	return nil
}
