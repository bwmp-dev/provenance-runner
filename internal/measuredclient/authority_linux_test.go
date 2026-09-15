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

func fixtureChannels(t *testing.T) []*cc.Channel {
	t.Helper()
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
		t.Cleanup(func() { channel.Close() })
	}
	return channels
}

func TestAuthorityForwarderRefusalClosesOwnedChannel(t *testing.T) {
	channels := fixtureChannels(t)
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

func TestReleaseIsOneShotAndSharesWriterSequence(t *testing.T) {
	channels := fixtureChannels(t)
	if channels[0].Send(cc.Packet{Kind: cc.Reconcile, Sequence: 1, Payload: []byte("synthetic")}, time.Now().Add(time.Second)) != nil {
		t.Fatal("initial test packet")
	}
	// Private byte-sequencing test only; no root-peer or launch claim.
	writer := &AuthorityForwarder{ctx: context.Background(), channel: channels[0], sequence: 1, cancel: func() {}, done: make(chan struct{})}
	if writer.Release(context.Background()) != nil || writer.Release(context.Background()) == nil {
		t.Fatal("release was not one-shot")
	}
	for sequence, kind := range []cc.Kind{cc.Reconcile, cc.Release} {
		packet, err := channels[1].Receive(time.Now().Add(time.Second))
		if err != nil || packet.Sequence != uint64(sequence+1) || packet.Kind != kind || len(packet.Files) != 0 {
			t.Fatal("writer sequence", err)
		}
		if kind == cc.Release && len(packet.Payload) != 0 {
			t.Fatal("release carries caller data")
		}
	}
}
