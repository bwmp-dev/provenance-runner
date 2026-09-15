package paper

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/guestoutput"
)

func TestMeasuredGuestLogsHaveSharedBound(t *testing.T) {
	var output bytes.Buffer
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)
	logs := &measuredGuestLogs{encoder: guestoutput.NewEncoder(&output), maximum: 5, cancel: cancel}
	out, errout := &measuredGuestLogStream{logs: logs, kind: guestoutput.Stdout}, &measuredGuestLogStream{logs: logs, kind: guestoutput.Stderr}
	if n, err := out.Write([]byte("123")); n != 3 || err != nil {
		t.Fatal(err)
	}
	if n, err := errout.Write([]byte("45")); n != 2 || err != nil {
		t.Fatal(err)
	}
	if n, err := out.Write([]byte("6")); n != 0 || err == nil || !errors.Is(context.Cause(ctx), ErrMeasuredGuest) {
		t.Fatal("log limit not shared")
	}
	for _, kind := range []guestoutput.Kind{guestoutput.Stdout, guestoutput.Stderr} {
		actual, _, err := guestoutput.Read(&output)
		if err != nil || kind != actual {
			t.Fatal("stream identity changed")
		}
	}
}
func TestMeasuredGuestCancelledEntryDoesNotExecute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if code, err := RunMeasuredGuest(ctx, nil, &out); code != 125 || err == nil || out.Len() != 0 {
		t.Fatal("cancelled guest entry admitted")
	}
}
