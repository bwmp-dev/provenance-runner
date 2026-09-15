package paper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/guestoutput"
)

var ErrMeasuredGuest = errors.New("measured_paper_guest_unavailable")

// RunMeasuredGuest is only the fixed non-root guest entry point. It has no host
// paths or command overrides and does not attest its own isolation. Host owners
// must independently enforce execution deadlines, drain framed output, withdraw
// authority and retire the whole sandbox before accepting a terminal result.
func RunMeasuredGuest(ctx context.Context, configuration []byte, output io.Writer) (code int, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 65532 || os.Getgid() != 65532 || output == nil {
		return 125, ErrMeasuredGuest
	}
	encoder := guestoutput.NewEncoder(output)
	defer func() {
		if result != nil {
			code = 125
		}
		raw, _ := json.Marshal(struct {
			ExitCode              int  `json:"exitCode"`
			InfrastructureFailure bool `json:"infrastructureFailure"`
		}{code, result != nil})
		result = errors.Join(result, encoder.Write(guestoutput.Outcome, raw))
	}()
	owned, err := prepareMeasuredGuest(ctx, configuration, "/inputs", "/workspace")
	if err != nil {
		return 125, ErrMeasuredGuest
	}
	defer func() { result = errors.Join(result, owned.workspace.Cleanup(context.Background())) }()
	const eventPath = "/tmp/provenance-probe-events.ndjson"
	events, err := os.OpenFile(eventPath, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 125, ErrMeasuredGuest
	}
	defer events.Close()
	identity, err := events.Stat()
	if err != nil || !identity.Mode().IsRegular() {
		return 125, ErrMeasuredGuest
	}
	defer func() {
		if current, err := os.Lstat(eventPath); err == nil && os.SameFile(identity, current) {
			_ = os.Remove(eventPath)
		}
	}()
	run, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)
	logs := &measuredGuestLogs{encoder: encoder, maximum: owned.maximumOutput, cancel: cancel}
	command := exec.CommandContext(run, owned.command, owned.arguments...)
	command.Dir, command.Env = owned.cwd, owned.environment
	command.Stdout, command.Stderr = &measuredGuestLogStream{logs: logs, kind: guestoutput.Stdout}, &measuredGuestLogStream{logs: logs, kind: guestoutput.Stderr}
	command.WaitDelay = time.Second
	err = command.Run()
	if run.Err() != nil {
		return 125, ErrMeasuredGuest
	}
	code = 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() < 0 || exit.ExitCode() > 255 {
			return 125, ErrMeasuredGuest
		}
		code = exit.ExitCode()
		if code == 125 {
			code = 126
		}
	}
	before, err := events.Stat()
	current, pathErr := os.Lstat(eventPath)
	if err != nil || pathErr != nil || !os.SameFile(identity, current) || !os.SameFile(identity, before) || before.Size() < 0 || before.Size() > 4<<20 {
		return 125, ErrMeasuredGuest
	}
	raw, err := io.ReadAll(io.NewSectionReader(events, 0, before.Size()+1))
	after, statErr := events.Stat()
	if err != nil || statErr != nil || int64(len(raw)) != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return 125, ErrMeasuredGuest
	}
	for len(raw) > 0 {
		n := len(raw)
		if n > guestoutput.MaximumChunk {
			n = guestoutput.MaximumChunk
		}
		if encoder.Write(guestoutput.Events, raw[:n]) != nil {
			return 125, ErrMeasuredGuest
		}
		raw = raw[n:]
	}
	return code, nil
}

type measuredGuestLogs struct {
	mu               sync.Mutex
	encoder          *guestoutput.Encoder
	maximum, written int64
	cancel           context.CancelCauseFunc
}
type measuredGuestLogStream struct {
	logs *measuredGuestLogs
	kind guestoutput.Kind
}

func (s *measuredGuestLogStream) Write(data []byte) (int, error) {
	l := s.logs
	l.mu.Lock()
	defer l.mu.Unlock()
	if int64(len(data)) > l.maximum-l.written {
		l.cancel(ErrMeasuredGuest)
		return 0, ErrMeasuredGuest
	}
	written := 0
	for len(data) > 0 {
		n := len(data)
		if n > guestoutput.MaximumChunk {
			n = guestoutput.MaximumChunk
		}
		if err := l.encoder.Write(s.kind, data[:n]); err != nil {
			l.cancel(ErrMeasuredGuest)
			return written, err
		}
		written += n
		l.written += int64(n)
		data = data[n:]
	}
	return written, nil
}
