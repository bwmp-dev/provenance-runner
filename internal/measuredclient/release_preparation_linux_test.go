//go:build linux

package measuredclient

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPreparedReleaseRechecksExpiryAuthorityAndCancellationAfterAcknowledgement(t *testing.T) {
	for _, mode := range []string{"current", "expired-before", "expired-during", "withdrawn-during", "cancelled-during", "ack-refused"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := time.Unix(100, 0)
			expires := now.Add(time.Second)
			current := true
			if mode == "expired-before" {
				now = expires
			}
			calls := 0
			err := acknowledgePreparedRelease(ctx, func(received context.Context) error {
				if received != ctx {
					t.Fatal("preparation context replaced")
				}
				calls++
				switch mode {
				case "expired-during":
					now = expires
				case "withdrawn-during":
					current = false
				case "cancelled-during":
					cancel()
				case "ack-refused":
					return errors.New("synthetic acknowledgement refusal")
				}
				return nil
			}, func() bool { return expires.After(now) && current })
			if (err == nil) != (mode == "current") || (calls == 0) != (mode == "expired-before") {
				t.Fatalf("release gate: mode=%s calls=%d err=%v", mode, calls, err)
			}
		})
	}
}
