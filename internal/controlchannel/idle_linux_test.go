//go:build linux

package controlchannel

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestServiceIdleProbeIsSeparateFromStart(t *testing.T) {
	for _, allow := range []bool{false, true} {
		sender, receiver := startChannels(t)
		nonce := bytes.Repeat([]byte{7}, 32)
		deadline := time.Now().Add(time.Second)
		if sender.Send(Packet{Kind: IdleCheck, Sequence: 1, Payload: nonce}, deadline) != nil {
			t.Fatal("probe send")
		}
		var request *StartRequest
		var err error
		if allow {
			request, err = ReceiveServiceRequest(receiver, deadline)
		} else {
			request, err = ReceiveStart(receiver, deadline)
		}
		if !allow {
			if err == nil || request != nil {
				t.Fatal("idle probe became execution")
			}
			continue
		}
		if err != nil || !bytes.Equal(request.IdleNonce, nonce) || len(request.Payload) != 0 || len(request.Files) != 0 || request.LastSequence != 1 {
			t.Fatal("idle probe acquired execution input", err)
		}
	}
}

func TestServiceIdleProbeRefusesMalformedAndClosesFiles(t *testing.T) {
	file := startFile(t)
	for _, packet := range []Packet{
		{Kind: IdleCheck},
		{Kind: IdleCheck, Payload: make([]byte, 33)},
		{Kind: IdleConfirmed, Payload: make([]byte, 32)},
		{Kind: IdleCheck, Payload: make([]byte, 32), Files: []*os.File{file}},
	} {
		sender, receiver := startChannels(t)
		before, _ := os.ReadDir("/proc/self/fd")
		packet.Sequence = 1
		deadline := time.Now().Add(time.Second)
		if sender.Send(packet, deadline) != nil {
			t.Fatal("send")
		}
		if request, err := ReceiveServiceRequest(receiver, deadline); err == nil || request != nil {
			t.Fatal("invalid idle accepted")
		}
		after, _ := os.ReadDir("/proc/self/fd")
		if len(after) != len(before)-1 {
			t.Fatal("refused probe did not close channel and received descriptors")
		}
	}
}
