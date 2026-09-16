//go:build linux

package measuredclient

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestSecretCapabilityRequiresRootAndClosesChannel(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("non-root refusal fixture")
	}
	pair := fixtureChannels(t)
	if CheckSecrets(context.Background(), pair[0]) == nil {
		t.Fatal("non-root capability accepted")
	}
	if _, err := pair[1].Receive(time.Now().Add(time.Second)); err == nil {
		t.Fatal("refused capability kept channel")
	}
	if CheckSecrets(nil, nil) == nil {
		t.Fatal("nil capability accepted")
	}
	pair = fixtureChannels(t)
	if maximum, err := ReadMaximum(context.Background(), pair[0]); maximum != nil || err == nil {
		t.Fatal("non-root maximum accepted")
	}
	if _, err := pair[1].Receive(time.Now().Add(time.Second)); err == nil {
		t.Fatal("refused maximum kept channel")
	}
	if maximum, err := ReadMaximum(nil, nil); maximum != nil || err == nil {
		t.Fatal("nil maximum accepted")
	}
}
