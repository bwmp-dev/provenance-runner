//go:build linux

package controlchannel

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestMaximumProbeSeparatedAndBounded(t *testing.T) {
	for _, allow := range []bool{false, true} {
		sender, receiver := startChannels(t)
		nonce := bytes.Repeat([]byte{3}, 32)
		deadline := time.Now().Add(time.Second)
		if sender.Send(Packet{Kind: MaximumCheck, Sequence: 1, Payload: nonce}, deadline) != nil {
			t.Fatal("send")
		}
		request, err := receiveStart(receiver, deadline, allow)
		if !allow {
			if request != nil || err == nil {
				t.Fatal("maximum became start")
			}
			continue
		}
		if err != nil || !bytes.Equal(request.MaximumNonce, nonce) || len(request.SecretNonce) != 0 || len(request.IdleNonce) != 0 || len(request.Payload) != 0 || len(request.Files) != 0 {
			t.Fatal("maximum probe acquired unrelated input")
		}
	}
	file := startFile(t)
	for _, packet := range []Packet{{Kind: MaximumCheck}, {Kind: MaximumCheck, Payload: make([]byte, 33)}, {Kind: MaximumConfirmed, Payload: make([]byte, 32)}, {Kind: MaximumCheck, Payload: make([]byte, 32), Files: []*os.File{file}}} {
		sender, receiver := startChannels(t)
		before, _ := os.ReadDir("/proc/self/fd")
		packet.Sequence = 1
		deadline := time.Now().Add(time.Second)
		if sender.Send(packet, deadline) != nil {
			t.Fatal("send")
		}
		if request, err := ReceiveServiceRequest(receiver, deadline); request != nil || err == nil {
			t.Fatal("malformed maximum accepted")
		}
		after, _ := os.ReadDir("/proc/self/fd")
		if len(after) != len(before)-1 {
			t.Fatal("maximum refusal leaked descriptors")
		}
	}
}
