//go:build linux

// Package measuredclient owns worker-side sessions with the root controller.
package measuredclient

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

var ErrSession = errors.New("measured_worker_session_refused")

type AuthorityForwarder struct {
	mu          sync.Mutex
	ctx         context.Context
	channel     *cc.Channel
	sequence    uint64
	released    bool
	secretsSent bool
	cancel      context.CancelFunc
	done        chan struct{}
	err         error
}

// DeliverSecrets borrows descriptors for one bounded, indivisible transfer.
// Reconciliation packets cannot interleave with its descriptor batches. Root
// independently checks selection, phase, expiry and sealed memory profiles.
func (w *AuthorityForwarder) DeliverSecrets(ctx context.Context, names []string, files []*os.File, expires time.Time) error {
	if w == nil || ctx == nil || ctx.Err() != nil {
		return ErrSession
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.released || w.secretsSent || w.cancel == nil || w.ctx == nil || w.ctx.Err() != nil {
		return ErrSession
	}
	w.secretsSent = true
	deadline := time.Now().Add(5 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	next, err := cc.SendSecrets(w.channel, names, files, expires, w.sequence, deadline)
	if err != nil {
		w.cancel()
		return ErrSession
	}
	w.sequence = next
	return nil
}

// StartAuthorityForwarder owns the channel and its one serialized writer.
// Release shares that writer with reconciliations; neither can reuse a sequence.
func StartAuthorityForwarder(ctx context.Context, channel *cc.Channel, guard *np.AuthorityRoute, job *p.JobSpecification, lastSequence uint64) (*AuthorityForwarder, error) {
	if channel == nil {
		return nil, ErrSession
	}
	peer, err := channel.PeerUID()
	if ctx == nil || ctx.Err() != nil || err != nil || peer != 0 || guard == nil || lastSequence == 0 || lastSequence == ^uint64(0) || guard.CheckJob(job) != nil {
		channel.Close()
		return nil, ErrSession
	}
	ctx, cancel := context.WithCancel(ctx)
	writer := &AuthorityForwarder{ctx: ctx, channel: channel, sequence: lastSequence, cancel: cancel, done: make(chan struct{})}
	go func() {
		writer.err = writer.run(ctx, guard)
		close(writer.done)
	}()
	return writer, nil
}

// Release is one-shot and carries no caller configuration. The root additionally
// requires that it has already sealed the live startup observation.
func (w *AuthorityForwarder) Release(ctx context.Context) error {
	if w == nil || ctx == nil || ctx.Err() != nil {
		return ErrSession
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.released || w.cancel == nil {
		return ErrSession
	}
	w.released = true
	if err := w.sendLocked(ctx, cc.Release, nil); err != nil {
		w.cancel()
		return err
	}
	return nil
}

// Close stops and joins only the local writer. It does not prove root cleanup;
// only an authenticated retired completion can establish that fact.
func (w *AuthorityForwarder) Close() {
	if w == nil || w.cancel == nil {
		return
	}
	w.cancel()
	<-w.done
}

func (w *AuthorityForwarder) Wait() error {
	if w == nil || w.done == nil {
		return ErrSession
	}
	<-w.done
	return w.err
}

func (w *AuthorityForwarder) sendLocked(ctx context.Context, kind cc.Kind, raw []byte) error {
	if w.channel == nil || ctx.Err() != nil || w.ctx == nil || w.ctx.Err() != nil || w.sequence == ^uint64(0) {
		return ErrSession
	}
	select {
	case <-w.done:
		return ErrSession
	default:
	}
	deadline := time.Now().Add(5 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	w.sequence++
	if w.channel.Send(cc.Packet{Kind: kind, Sequence: w.sequence, Payload: raw}, deadline) != nil {
		return ErrSession
	}
	return nil
}

// ForwardAuthority is the sole writer after SendStart. lastSequence is the
// cursor returned by SendStart. It forwards only live supervisor updates for
// this job, never caller-synthesized heartbeats or renewed timestamps. The
// function owns the channel on every path and closes it on any forwarding loss;
// readers may concurrently consume observation and result packets. Cancel this
// context only after consuming the root completion or abandoning the session.
func ForwardAuthority(ctx context.Context, channel *cc.Channel, guard *np.AuthorityRoute, job *p.JobSpecification, lastSequence uint64) error {
	writer, err := StartAuthorityForwarder(ctx, channel, guard, job, lastSequence)
	if err != nil {
		return err
	}
	defer writer.Close()
	return writer.Wait()
}

func (w *AuthorityForwarder) run(ctx context.Context, guard *np.AuthorityRoute) error {
	defer w.channel.Close()
	finished, watched := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watched)
		select {
		case <-ctx.Done():
			w.channel.Close()
		case <-guard.Done():
			w.channel.Close()
		case <-finished:
		}
	}()
	defer func() { close(finished); <-watched }()
	cursor := uint64(0)
	for packets := 0; packets < 8192; packets++ {
		next, raw, err := guard.NextControlUpdate(ctx, cursor)
		if err != nil {
			return ErrSession
		}
		w.mu.Lock()
		err = w.sendLocked(ctx, cc.Reconcile, raw)
		w.mu.Unlock()
		if err != nil {
			return ErrSession
		}
		cursor = next
	}
	return ErrSession
}
