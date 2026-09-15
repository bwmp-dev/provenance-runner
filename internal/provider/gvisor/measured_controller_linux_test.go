//go:build linux

package gvisor

import (
	"context"
	"testing"
	"time"
)

func TestMeasuredControllerRequiresOwnedProvisioning(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if c, err := newMeasuredController(ctx, measuredControllerConfig{}); c != nil || err == nil {
			t.Fatal("empty controller admitted")
		}
	}
	var c *measuredController
	if c.Close(context.Background()) != nil {
		t.Fatal("nil controller cleanup")
	}
	if j, err := c.start(context.Background(), nil, measuredGuestCommand{}, nil, nil, nil, nil, nil); j != nil || err == nil {
		t.Fatal("nil controller admission")
	}
	var j *measuredControllerJob
	if j.Close(context.Background()) != nil || j.Release(context.Background()) == nil || j.Wait(context.Background()) == nil {
		t.Fatal("nil controller job")
	}
	if controllerRootMatches("/", nil) || controllerRootMatches("relative", &measuredBundleJournal{}) {
		t.Fatal("unowned root admitted")
	}
}

func TestMeasuredBudgetClaimCannotResetStagingClock(t *testing.T) {
	b, err := newMeasuredSessionBudget(context.Background(), time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	deadline := b.deadline
	if b.claim(2*time.Second, time.Second) == nil {
		t.Fatal("different phase budget claimed")
	}
	if b.claim(time.Second, time.Second) != nil || b.claim(time.Second, time.Second) == nil || !b.deadline.Equal(deadline) {
		t.Fatal("budget claim reset or reused")
	}
}
