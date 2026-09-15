//go:build linux

package gvisor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func awaitSessionBudget(t *testing.T, b *measuredSessionBudget) {
	t.Helper()
	select {
	case <-b.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("session budget did not cancel")
	}
}

func TestMeasuredSessionBudgetPreparationAndExecution(t *testing.T) {
	preparation, err := newMeasuredSessionBudget(context.Background(), 10*time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer preparation.close()
	awaitSessionBudget(t, preparation)
	if !errors.Is(context.Cause(preparation.ctx), context.DeadlineExceeded) || preparation.beginExecution() == nil {
		t.Fatal("expired preparation resumed")
	}
	execution, err := newMeasuredSessionBudget(context.Background(), time.Second, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer execution.close()
	if execution.beginExecution() != nil {
		t.Fatal("execution budget refused")
	}
	awaitSessionBudget(t, execution)
	if !errors.Is(context.Cause(execution.ctx), context.DeadlineExceeded) || execution.beginExecution() == nil {
		t.Fatal("execution deadline reset")
	}
	if execution.active() {
		t.Fatal("expired execution observation admitted")
	}
}

func TestMeasuredSessionBudgetStopsPreviousPhase(t *testing.T) {
	b, err := newMeasuredSessionBudget(context.Background(), 100*time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if b.beginExecution() != nil {
		t.Fatal("release refused")
	}
	select {
	case <-b.ctx.Done():
		t.Fatal("old phase timer killed execution")
	case <-time.After(150 * time.Millisecond):
	}
	if !b.active() {
		t.Fatal("live execution budget unavailable")
	}
	if b.beginExecution() == nil {
		t.Fatal("second release extended execution")
	}
	awaitSessionBudget(t, b)
}

func TestMeasuredSessionBudgetRejectsInvalidAndPropagatesParent(t *testing.T) {
	for _, parent := range []context.Context{nil, context.Background()} {
		if b, err := newMeasuredSessionBudget(parent, 0, time.Second); b != nil || err == nil {
			t.Fatal("unbounded preparation")
		}
	}
	parent, cancel := context.WithCancelCause(context.Background())
	b, err := newMeasuredSessionBudget(parent, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	cause := errors.New("parent-lost")
	cancel(cause)
	awaitSessionBudget(t, b)
	if !errors.Is(context.Cause(b.ctx), cause) || b.beginExecution() == nil {
		t.Fatal("parent cancellation lost")
	}
	var absent *measuredSessionBudget
	absent.close()
	if absent.beginExecution() == nil {
		t.Fatal("missing budget")
	}
	empty := &measuredSessionBudget{}
	empty.close()
	if empty.beginExecution() == nil {
		t.Fatal("empty budget")
	}
}
