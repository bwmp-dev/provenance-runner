//go:build linux

package main

import (
	"net"
	"os"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/controlchannel"
)

func init() { measuredControlClient = runControlClient }

func runControlClient() bool {
	if len(os.Args) != 3 || os.Args[1] != "control-client" {
		return false
	}
	if os.Getuid() != 65532 || os.Getgid() != 65532 || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		panic("disposable control client required")
	}
	conn, err := net.DialTimeout("unixpacket", os.Args[2], 3*time.Second)
	if err != nil {
		panic(err)
	}
	channel, err := controlchannel.New(conn.(*net.UnixConn), 0)
	if err != nil {
		conn.Close()
		panic(err)
	}
	defer channel.Close()
	deadline := time.Now().Add(3 * time.Second)
	if channel.Send(controlchannel.Packet{Kind: controlchannel.Cancel, Sequence: 1, Payload: []byte("synthetic peer")}, deadline) != nil {
		panic("control request")
	}
	reply, err := channel.Receive(deadline)
	if err != nil || reply.Kind != controlchannel.Result || string(reply.Payload) != "accepted" || len(reply.Files) != 0 {
		panic("control reply")
	}
	return true
}
