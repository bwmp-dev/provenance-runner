//go:build linux

package runtimeidentity

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPinnedAcquisitionRefusesBeforeOtherObjectsOrVersion(t *testing.T) {
	pins := ExpectedObjects{RunnerSHA256: strings.Repeat("1", 64), SandboxSHA256: strings.Repeat("2", 64), RootFSSHA256: strings.Repeat("3", 64)}
	if lease, err := AcquirePinned(context.Background(), "/must-not-be-opened", "/missing-root", "/missing-image", pins); lease != nil || !errors.Is(err, ErrDrift) {
		t.Fatal("runner pin was not checked before other objects", err)
	}
	for _, invalid := range []ExpectedObjects{{}, {RunnerSHA256: strings.Repeat("0", 64), SandboxSHA256: pins.SandboxSHA256, RootFSSHA256: pins.RootFSSHA256}, {RunnerSHA256: strings.Repeat("A", 64), SandboxSHA256: pins.SandboxSHA256, RootFSSHA256: pins.RootFSSHA256}} {
		if lease, err := AcquirePinned(context.Background(), "/must-not-be-opened", "/missing-root", "/missing-image", invalid); lease != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid deployment pins accepted", err)
		}
	}
	if lease, err := AcquirePinned(nil, "/missing", "/missing", "/missing", pins); lease != nil || err == nil {
		t.Fatal("nil context accepted")
	}
}
