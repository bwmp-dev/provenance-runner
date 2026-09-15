//go:build linux

package controlchannel

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRootObservationReceiptCannotBeDecodedOrUseNonRootPeer(t *testing.T) {
	var packet RootObservationPacket
	if json.Unmarshal([]byte(`{"authenticated":true,"payload":"forged"}`), &packet) != nil {
		t.Fatal("fixture JSON")
	}
	if raw, ok := packet.Payload(); ok || len(raw) != 0 {
		t.Fatal("JSON fabricated root receipt")
	}
	if os.Getuid() == 0 {
		t.Skip("ordinary non-root peer refusal")
	}
	left, _ := pair(t, unix.SOCK_SEQPACKET)
	channel, err := New(left, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := channel.ReceiveRootObservation(time.Now().Add(time.Second)); receipt != nil || err == nil {
		t.Fatal("non-root peer supplied root observation")
	}
}
