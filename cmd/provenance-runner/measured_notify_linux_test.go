//go:build linux

package main

import (
	"context"
	"errors"
	"testing"
)

func TestMeasuredReadyNotificationIsClosedAndOptional(t *testing.T) {
	for _, socket := range []string{"", "/run/systemd/notify", "@foreign", "/tmp/socket", "/run/systemd/../notify", "/run/systemd/notify\x00"} {
		calls := 0
		err := notifyMeasuredReady(context.Background(), socket, func(payload []byte) error {
			calls++
			if string(payload) != "READY=1" {
				t.Fatal("unexpected notification data")
			}
			return nil
		})
		valid := socket == "" || socket == "/run/systemd/notify"
		if (err == nil) != valid || calls != map[bool]int{true: 1, false: 0}[socket == "/run/systemd/notify"] {
			t.Fatalf("notification boundary for %q", socket)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if notifyMeasuredReady(ctx, "/run/systemd/notify", func([]byte) error { t.Fatal("cancelled readiness"); return nil }) == nil {
			t.Fatal("invalid context accepted")
		}
	}
	if notifyMeasuredReady(context.Background(), "/run/systemd/notify", nil) == nil {
		t.Fatal("missing notifier accepted")
	}
	expected := errors.New("notification unavailable")
	if !errors.Is(notifyMeasuredReady(context.Background(), "/run/systemd/notify", func([]byte) error { return expected }), expected) {
		t.Fatal("failed readiness became successful admission")
	}
}
