//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
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
