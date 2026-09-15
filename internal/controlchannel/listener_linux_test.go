//go:build linux

package controlchannel

import (
	"os"
	"testing"
	"time"
)

func TestRootListenerRefusesMissingOrUnprivilegedProvisioning(t *testing.T) {
	if listener, err := OpenRootListener(nil, 994, 981); err == nil || listener != nil {
		t.Fatal("missing directory admitted")
	}
	parent, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	for _, ids := range [][2]uint32{{0, 1}, {1, 0}, {^uint32(0), 1}, {1, ^uint32(0)}, {994, 981}} {
		if listener, err := OpenRootListener(parent, ids[0], ids[1]); err == nil || listener != nil {
			t.Fatal("unprovisioned listener admitted")
		}
	}
	var absent *RootListener
	if absent.Close() != nil {
		t.Fatal("nil close")
	}
	if channel, err := absent.Accept(time.Now().Add(time.Second)); channel != nil || err == nil {
		t.Fatal("nil accept")
	}
}
