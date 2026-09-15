//go:build linux

package testsecrets_test

import (
	"net"
	"os"
	"testing"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	"golang.org/x/sys/unix"
)

// This is an actual SCM_RIGHTS round trip, not root-service authorization or
// production secret delivery. Both peers use the test process's actual UID.
func TestSealedDescriptorsCrossReadonlyChannel(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var channels []*cc.Channel
	for _, fd := range fds {
		file := os.NewFile(uintptr(fd), "secret-channel-fixture")
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		channel, err := cc.New(conn.(*net.UnixConn), uint32(os.Getuid()))
		if err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		defer channel.Close()
		channels = append(channels, channel)
	}
	owner, err := ts.New([]ts.Input{{Name: "license", Value: []byte("synthetic-channel-value")}})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	views, err := owner.ReadOnlyDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	defer views[0].File.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := channels[0].Send(cc.Packet{Kind: cc.Start, Sequence: 1, Files: []*os.File{views[0].File}}, deadline); err != nil {
		t.Fatal(err)
	}
	packet, err := channels[1].Receive(deadline)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range packet.Files {
		defer file.Close()
	}
	if len(packet.Files) != 1 {
		t.Fatal("missing received descriptor")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := views[0].File.Close(); err != nil {
		t.Fatal(err)
	}
	value, err := ts.ReadSealedDescriptor(packet.Files[0])
	defer clear(value)
	if err != nil || string(value) != "synthetic-channel-value" {
		t.Fatal("received sealed profile or contents invalid")
	}
}
