package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestMeasuredServiceCancellationRefusesBeforeConfiguration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, diagnostics bytes.Buffer
	code := runContext(ctx, []string{"measured-service", "/configuration-must-not-be-opened"}, strings.NewReader(""), &out, &diagnostics)
	if code != 1 || out.Len() != 0 || !strings.Contains(diagnostics.String(), "requires") {
		t.Fatal("root service entered another command or read private configuration")
	}
}
