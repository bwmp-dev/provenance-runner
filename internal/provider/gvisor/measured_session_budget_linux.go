//go:build linux

package gvisor

import (
	"context"
	"sync"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/localjob"
)

// A budget owns cancellation, not process cleanup. Its caller must keep every
// cleanup owner until whole-session retirement succeeds after cancellation.
type measuredSessionBudget struct {
	mu               sync.Mutex
	ctx              context.Context
	cancel           context.CancelCauseFunc
	timer            *time.Timer
	deadline         time.Time
	execution        time.Duration
	preparation      time.Duration
	claimed          bool
	released, closed bool
}

func newMeasuredSessionBudget(parent context.Context, preparation, execution time.Duration) (*measuredSessionBudget, error) {
	if parent == nil || parent.Err() != nil || preparation <= 0 || execution <= 0 || preparation > localjob.MaximumTimeout || execution > localjob.MaximumTimeout {
		return nil, errMeasuredSession
	}
	ctx, cancel := context.WithCancelCause(parent)
	b := &measuredSessionBudget{ctx: ctx, cancel: cancel, deadline: time.Now().Add(preparation), execution: execution, preparation: preparation}
	b.timer = time.AfterFunc(preparation, func() { cancel(context.DeadlineExceeded) })
	return b, nil
}

func (b *measuredSessionBudget) claim(preparation, execution time.Duration) error {
	if b == nil {
		return errMeasuredSession
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx == nil || b.claimed || b.closed || b.released || b.ctx.Err() != nil || !time.Now().Before(b.deadline) || b.preparation != preparation || b.execution != execution {
		return errMeasuredSession
	}
	b.claimed = true
	return nil
}

// beginExecution is one-shot and precedes opening the workload gate. It cannot
// revive a timed-out construction phase or reset an already running deadline.
func (b *measuredSessionBudget) beginExecution() error {
	if b == nil {
		return errMeasuredSession
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx == nil || b.cancel == nil || b.timer == nil {
		return errMeasuredSession
	}
	if b.closed || b.released || b.ctx.Err() != nil || !time.Now().Before(b.deadline) || !b.timer.Stop() {
		b.cancel(context.DeadlineExceeded)
		return errMeasuredSession
	}
	b.released = true
	b.deadline = time.Now().Add(b.execution)
	b.timer = time.AfterFunc(b.execution, func() { b.cancel(context.DeadlineExceeded) })
	return nil
}

func (b *measuredSessionBudget) close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	if b.timer != nil {
		b.timer.Stop()
	}
	if b.cancel != nil {
		b.cancel(context.Canceled)
	}
}

func (b *measuredSessionBudget) active() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx == nil || b.closed || !b.released || b.ctx.Err() != nil {
		return false
	}
	if !time.Now().Before(b.deadline) {
		b.cancel(context.DeadlineExceeded)
		return false
	}
	return true
}
