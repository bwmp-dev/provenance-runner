//go:build linux

package controlchannel

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestSecretProbeCannotBecomeStartOrIdle(t *testing.T) {
	for _, allow := range []bool{false, true} {
		sender, receiver := startChannels(t)
		nonce := bytes.Repeat([]byte{9}, 32)
		deadline := time.Now().Add(time.Second)
		if sender.Send(Packet{Kind: SecretCheck, Sequence: 1, Payload: nonce}, deadline) != nil {
			t.Fatal("probe send")
		}
		request, err := receiveStart(receiver, deadline, allow)
		if !allow {
			if err == nil || request != nil {
				t.Fatal("capability became start")
			}
			continue
		}
		if err != nil || !bytes.Equal(request.SecretNonce, nonce) || len(request.IdleNonce) != 0 || len(request.Payload) != 0 || len(request.Files) != 0 || request.LastSequence != 1 {
			t.Fatal("capability probe confused with other request", err)
		}
	}
}

func TestSecretProbeMalformedClosesReceivedFiles(t *testing.T) {
	file := startFile(t)
	for _, packet := range []Packet{
		{Kind: SecretCheck}, {Kind: SecretCheck, Payload: make([]byte, 33)},
		{Kind: SecretConfirmed, Payload: make([]byte, 32)},
		{Kind: SecretCheck, Payload: make([]byte, 32), Files: []*os.File{file}},
	} {
		sender, receiver := startChannels(t)
		before, _ := os.ReadDir("/proc/self/fd")
		packet.Sequence = 1
		deadline := time.Now().Add(time.Second)
		if sender.Send(packet, deadline) != nil {
			t.Fatal("send")
		}
		if request, err := ReceiveServiceRequest(receiver, deadline); err == nil || request != nil {
			t.Fatal("malformed capability admitted")
		}
		after, _ := os.ReadDir("/proc/self/fd")
		if len(after) != len(before)-1 {
			t.Fatal("refused probe leaked ownership")
		}
	}
}
