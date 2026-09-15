//go:build !linux

package main

import (
	"context"
	"fmt"
	"io"
)

func runMeasuredService(_ context.Context, _ string, stderr io.Writer) int {
	fmt.Fprintln(stderr, "measured service requires Linux root provisioning")
	return 1
}
