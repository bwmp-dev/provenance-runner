//go:build linux

package measuredclient

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
)

func TestSecretDeliverySharesOneShotWriterSequence(t *testing.T) {
	channels := fixtureChannels(t)
	until := time.Now().Add(time.Second)
	if channels[0].Send(cc.Packet{Kind: cc.Reconcile, Sequence: 1}, until) != nil {
		t.Fatal("initial packet")
	}
	if _, err := channels[1].Receive(until); err != nil {
		t.Fatal(err)
	}
	var inputs []ts.Input
	var names []string
	for i := 0; i < 17; i++ {
		name := fmt.Sprintf("secret-%02d", i)
		names = append(names, name)
		inputs = append(inputs, ts.Input{Name: name, Value: []byte("synthetic")})
	}
	owner, err := ts.New(inputs)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	views, err := owner.ReadOnlyDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	var files []*os.File
	for _, view := range views {
		files = append(files, view.File)
		defer view.File.Close()
	}
	// Private transport test; same-UID sockets are not root authentication.
	writer := &AuthorityForwarder{ctx: context.Background(), channel: channels[0], sequence: 1, cancel: func() {}, done: make(chan struct{})}
	expires := time.Now().Add(time.Minute)
	if writer.DeliverSecrets(context.Background(), names, files, expires) != nil || writer.DeliverSecrets(context.Background(), names, files, expires) == nil {
		t.Fatal("one-shot delivery")
	}
	first, err := channels[1].Receive(until)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := cc.ReceiveSecrets(channels[1], first, names, expires, until)
	if err != nil {
		t.Fatal(err)
	}
	defer delivery.Close()
	if len(delivery.Files) != 17 || writer.sequence != 4 {
		t.Fatal("batched cursor")
	}
	if writer.Release(context.Background()) != nil {
		t.Fatal("release")
	}
	packet, err := channels[1].Receive(until)
	if err != nil || packet.Kind != cc.Release || packet.Sequence != 5 {
		t.Fatal("release sequence")
	}
	if writer.DeliverSecrets(context.Background(), names, files, expires) == nil {
		t.Fatal("post-release delivery")
	}
}

func TestSecretDeliveryRefusesUnownedWriter(t *testing.T) {
	for _, writer := range []*AuthorityForwarder{nil, {}, {released: true}, {secretsSent: true}} {
		if writer.DeliverSecrets(context.Background(), nil, nil, time.Now().Add(time.Minute)) == nil {
			t.Fatal("unowned writer")
		}
	}
}
