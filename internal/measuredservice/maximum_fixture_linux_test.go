//go:build linux

package measuredservice

import (
	"context"
	"os"
	"testing"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/measuredclient"
	"google.golang.org/protobuf/proto"
)

func maximumRefusalFixture(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Fatal("disposable root required")
	}
	_, _, job := serviceFixtureJob(t, []byte("synthetic java"), []byte("synthetic prepared"))
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(job.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "nonce", "kind", "short", "files", "eof", "oversize", "noncanonical", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			client, root := testChannels(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				maximum, err := measuredclient.ReadMaximum(ctx, client)
				if mode == "valid" && !proto.Equal(maximum, job.EffectivePolicy) {
					t.Error("maximum changed")
				}
				done <- err
			}()
			request, err := cc.ReceiveServiceRequest(root, time.Now().Add(time.Second))
			if err != nil || len(request.MaximumNonce) != 32 || len(request.IdleNonce) != 0 || len(request.SecretNonce) != 0 {
				t.Fatal("maximum request", err)
			}
			response := cc.Packet{Kind: cc.MaximumConfirmed, Sequence: 1, Payload: append(request.MaximumNonce, raw...)}
			switch mode {
			case "nonce":
				response.Payload[0] ^= 1
			case "kind":
				response.Kind = cc.SecretConfirmed
			case "short":
				response.Payload = response.Payload[:32]
			case "files":
				file, err := os.Open(os.Args[0])
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				response.Files = []*os.File{file}
			case "eof":
				root.Close()
			case "oversize":
				response.Payload = append(response.Payload[:32], make([]byte, (16<<10)+1)...)
			case "noncanonical":
				response.Payload = append(response.Payload, raw...)
			case "unknown":
				response.Payload = append(response.Payload, 0xa0, 0x06, 0x01)
			}
			if mode != "eof" && root.Send(response, time.Now().Add(time.Second)) != nil {
				t.Fatal("maximum response")
			}
			if err := <-done; (err == nil) != (mode == "valid") {
				t.Fatal("maximum response acceptance", mode, err)
			}
		})
	}
}
