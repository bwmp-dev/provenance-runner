//go:build linux

package measuredclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

// ReadMaximum consumes a fresh root-authenticated channel. The nonce-bound
// response contains only immutable public policy limits, not paths or secrets.
// It is not a lease grant or permission to resume an earlier session.
func ReadMaximum(ctx context.Context, channel *cc.Channel) (*p.EffectivePolicy, error) {
	if channel == nil {
		return nil, ErrSession
	}
	defer channel.Close()
	peer, err := channel.PeerUID()
	if ctx == nil || ctx.Err() != nil || err != nil || peer != 0 {
		return nil, ErrSession
	}
	stop := context.AfterFunc(ctx, func() { channel.Close() })
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil || channel.Send(cc.Packet{Kind: cc.MaximumCheck, Sequence: 1, Payload: nonce}, deadline) != nil {
		return nil, ErrSession
	}
	packet, err := channel.Receive(deadline)
	for _, file := range packet.Files {
		file.Close()
	}
	if err != nil || ctx.Err() != nil || len(packet.Files) != 0 || packet.Kind != cc.MaximumConfirmed || packet.Sequence != 1 || len(packet.Payload) <= 32 || len(packet.Payload) > 32+(16<<10) || !bytes.Equal(packet.Payload[:32], nonce) {
		return nil, ErrSession
	}
	var maximum p.EffectivePolicy
	raw := packet.Payload[32:]
	if proto.Unmarshal(raw, &maximum) != nil {
		return nil, ErrSession
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(&maximum)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrSession
	}
	if _, err := networkpolicy.EffectivePolicyV2SHA256(&maximum); err != nil || maximum.Sandbox != p.SandboxKind_SANDBOX_KIND_GVISOR {
		return nil, ErrSession
	}
	return &maximum, nil
}
