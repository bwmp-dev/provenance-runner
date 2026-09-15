//go:build linux

package measuredclient

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"golang.org/x/sys/unix"
)

func TestAuthorityForwarderRefusalClosesOwnedChannel(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var channels []*cc.Channel
	for _, fd := range fds {
		file := os.NewFile(uintptr(fd), "fixture channel")
		connection, err := net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		channel, err := cc.New(connection.(*net.UnixConn), uint32(os.Getuid()))
		if err != nil {
			connection.Close()
			t.Fatal(err)
		}
		channels = append(channels, channel)
		defer channel.Close()
	}
	// Admission/ownership only. Same-UID test sockets are not root-peer proof.
	if err := ForwardAuthority(context.Background(), channels[0], nil, nil, 0); err == nil {
		t.Fatal("unprovisioned forwarding accepted")
	}
	if _, err := channels[1].Receive(time.Now().Add(time.Second)); err == nil {
		t.Fatal("refused forwarder retained socket")
	}
	if err := ForwardAuthority(nil, nil, nil, nil, 0); err == nil {
		t.Fatal("absent channel accepted")
	}
}
