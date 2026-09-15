//go:build linux

package measuredclient

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestSessionFailureJSONCannotProveRetirement(t *testing.T) {
	var failure SessionFailure
	if err := json.Unmarshal([]byte(`{"observation":{},"completion":{"authenticated":true}}`), &failure); err != nil {
		t.Fatal(err)
	}
	for _, value := range []*SessionFailure{nil, &failure} {
		if value.RetiredFor(nil) || !errors.Is(value, ErrSession) {
			t.Fatal("failure manufactured retirement or lost failure classification")
		}
	}
}

func TestSessionResultCannotBeConstructedFromJSON(t *testing.T) {
	var result SessionResult
	if err := json.Unmarshal([]byte(`{"observation":{},"completion":{"exit":0,"authenticated":true}}`), &result); err != nil {
		t.Fatal(err)
	}
	for _, value := range []*SessionResult{nil, &result} {
		if _, _, err := value.Outcome(); err == nil || value.Observation() != nil {
			t.Fatal("unreceived result became authentic")
		}
	}
}

func TestUnprovisionedSessionClosesOwnedChannel(t *testing.T) {
	channels := fixtureChannels(t)
	if result, err := Run(context.Background(), channels[0], nil, SessionOptions{}, nil); result != nil || err == nil {
		t.Fatal("unprovisioned session accepted")
	}
	if _, err := channels[1].Receive(time.Now().Add(time.Second)); err == nil {
		t.Fatal("failed session retained channel")
	}
}
