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

// Protocol checks only; actual controller capability is tested separately.
func secretProbeRefusalFixture(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Fatal("disposable root required")
	}
	for _, mode := range []string{"valid", "nonce", "idle", "short", "files", "eof"} {
		t.Run(mode, func(t *testing.T) {
			client, root := testChannels(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- measuredclient.CheckSecrets(ctx, client) }()
			request, err := cc.ReceiveServiceRequest(root, time.Now().Add(time.Second))
			if err != nil || len(request.SecretNonce) != 32 || len(request.IdleNonce) != 0 {
				t.Fatal("secret capability request", err)
			}
			response := cc.Packet{Kind: cc.SecretConfirmed, Sequence: 1, Payload: request.SecretNonce}
			switch mode {
			case "nonce":
				response.Payload[0] ^= 1
			case "idle":
				response.Kind = cc.IdleConfirmed
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
				t.Fatal("capability response")
			}
			if err := <-done; (err == nil) != (mode == "valid") {
				t.Fatal("capability response acceptance", mode, err)
			}
		})
	}
}
