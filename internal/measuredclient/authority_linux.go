//go:build linux

// Package measuredclient owns worker-side sessions with the root controller.
package measuredclient

import (
	"context"
	"errors"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

var ErrSession = errors.New("measured_worker_session_refused")

// ForwardAuthority is the sole writer after SendStart. lastSequence is the
// cursor returned by SendStart. It forwards only live supervisor updates for
// this job, never caller-synthesized heartbeats or renewed timestamps. The
// function owns the channel on every path and closes it on any forwarding loss;
// readers may concurrently consume observation and result packets. Cancel this
// context only after consuming the root completion or abandoning the session.
func ForwardAuthority(ctx context.Context, channel *cc.Channel, guard *np.AuthorityRoute, job *p.JobSpecification, lastSequence uint64) error {
	if channel == nil {
		return ErrSession
	}
	defer channel.Close()
	peer, err := channel.PeerUID()
	if ctx == nil || ctx.Err() != nil || err != nil || peer != 0 || guard == nil || lastSequence == 0 || lastSequence == ^uint64(0) || guard.CheckJob(job) != nil {
		return ErrSession
	}
	finished, watched := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watched)
		select {
		case <-ctx.Done():
			channel.Close()
		case <-guard.Done():
			channel.Close()
		case <-finished:
		}
	}()
	defer func() { close(finished); <-watched }()
	cursor := uint64(0)
	for packets := 0; packets < 8192; packets++ {
		next, raw, err := guard.NextControlUpdate(ctx, cursor)
		if err != nil || lastSequence == ^uint64(0) {
			return ErrSession
		}
		deadline := time.Now().Add(5 * time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		lastSequence++
		if err := channel.Send(cc.Packet{Kind: cc.Reconcile, Sequence: lastSequence, Payload: raw}, deadline); err != nil {
			return ErrSession
		}
		cursor = next
	}
	return ErrSession
}
