//go:build linux

package gvisor

import (
	"context"
	"strings"
	"testing"
)

func TestMeasuredInputNamesCannotSelectHostPaths(t *testing.T) {
	for _, name := range []string{"candidate.jar", "paper-26.2.jar", "A_1"} {
		if !measuredInputName.MatchString(name) {
			t.Fatal("bounded input alias refused")
		}
	}
	for _, name := range []string{"", ".", "..", ".owner", "../candidate.jar", "/etc/passwd", "a/b", "a\\b", "a\n", "a\x00", strings.Repeat("x", 129)} {
		if measuredInputName.MatchString(name) {
			t.Fatal("host path or ambiguous alias admitted")
		}
	}
}

func TestMeasuredInputStagingNeedsOwnedDirectory(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if stageMeasuredInputs(ctx, nil, nil, 1) == nil {
			t.Fatal("missing private directory accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if stageMeasuredInputs(ctx, nil, nil, 1) == nil || localInputFilesystem(nil) {
		t.Fatal("absent staging authority accepted")
	}
}
