package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
)

func main() {
	if len(os.Args) != 1 || os.Getuid() != 65532 || os.Getgid() != 65532 {
		os.Exit(125)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		os.Exit(125)
	}
	code, err := paper.RunMeasuredGuest(ctx, raw, os.Stdout)
	if err != nil {
		os.Exit(125)
	}
	os.Exit(code)
}
