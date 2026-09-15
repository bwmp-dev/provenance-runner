//go:build linux

package measuredservice

import (
	"context"
	"os"
	"testing"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/measuredclient"
)

// Called only inside the explicit disposable root fixture. These authenticated
// root socket responses deliberately violate the idle protocol; they are not
// controller readiness claims. Real service replies are exercised separately.
func idleRefusalFixture(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Fatal("disposable root required")
	}
	for _, mode := range []string{"nonce", "kind", "short", "files", "eof"} {
		t.Run(mode, func(t *testing.T) {
			client, root := testChannels(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- measuredclient.CheckIdle(ctx, client) }()
			request, err := cc.ReceiveServiceRequest(root, time.Now().Add(time.Second))
			if err != nil || len(request.IdleNonce) != 32 {
				t.Fatal("idle request", err)
			}
			response := cc.Packet{Kind: cc.IdleConfirmed, Sequence: 1, Payload: request.IdleNonce}
			switch mode {
			case "nonce":
				response.Payload[0] ^= 1
			case "kind":
				response.Kind = cc.Completion
			case "short":
				response.Payload = response.Payload[:31]
			case "files":
				file, err := os.Open(os.Args[0])
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				response.Files = []*os.File{file}
			case "eof":
				root.Close()
			}
			if mode != "eof" && root.Send(response, time.Now().Add(time.Second)) != nil {
				t.Fatal("idle response")
			}
			if err := <-done; err == nil {
				t.Fatal("invalid root response became idle capacity")
			}
		})
	}
}
