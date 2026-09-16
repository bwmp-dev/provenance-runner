//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/measuredservice"
)

func runMeasuredService(ctx context.Context, path string, stderr io.Writer) int {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || syscall.Setgroups([]int{}) != nil {
		fmt.Fprintln(stderr, "measured service requires root provisioning")
		return 1
	}
	// This command never enters connect/enrollment or reads their credentials.
	config, err := measuredservice.LoadDaemonConfig(ctx, path)
	if err != nil {
		fmt.Fprintln(stderr, "measured service configuration refused")
		return 1
	}
	daemon, err := measuredservice.OpenDaemon(ctx, *config)
	if err == nil {
		err = notifyMeasuredReady(ctx, os.Getenv("NOTIFY_SOCKET"), sendMeasuredReady)
	}
	if err == nil {
		err = daemon.Serve()
	}
	warned := false
	for daemon != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closed := daemon.Close(cleanup)
		cancel()
		if closed == nil {
			break
		}
		if !warned {
			fmt.Fprintln(stderr, "measured service cleanup pending; admission stopped and ownership retained")
			warned = true
		}
		// Deliberately outlive caller cancellation: process exit cannot claim
		// retirement. An operator may repair ownership drift for this retry.
		time.Sleep(time.Second)
	}
	if err != nil && ctx.Err() == nil {
		fmt.Fprintln(stderr, "measured service stopped after refusal")
		return 1
	}
	return 0
}

// Only the root system manager's fixed socket is accepted. Child runtimes use
// their existing closed environments and never inherit notification authority.
func notifyMeasuredReady(ctx context.Context, socket string, send func([]byte) error) error {
	if ctx == nil || ctx.Err() != nil || (socket != "" && socket != "/run/systemd/notify") {
		return measuredservice.ErrService
	}
	if socket == "" {
		return nil // Direct operator invocation and disposable fixtures.
	}
	if send == nil {
		return measuredservice.ErrService
	}
	return send([]byte("READY=1"))
}

func sendMeasuredReady(payload []byte) error {
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: "/run/systemd/notify", Net: "unixgram"})
	if err != nil {
		return measuredservice.ErrService
	}
	defer connection.Close()
	if connection.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
		return measuredservice.ErrService
	}
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		return measuredservice.ErrService
	}
	return nil
}
