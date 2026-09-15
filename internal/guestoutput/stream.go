package guestoutput

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
)

const (
	MaximumLogBytes   = 16 << 20
	MaximumEventBytes = 4 << 20
	MaximumFrames     = 16384
)

var ErrStream = errors.New("guest_output_stream_invalid")

// Transcript contains only untrusted guest claims, never process or isolation
// evidence. A caller must observe actual exit and complete sandbox retirement,
// and validate provider event schemas, before interpreting a job result.
type Transcript struct {
	exitCode              int
	infrastructureFailure bool
	events                []byte
	logBytes              int64
}

func (t *Transcript) ClaimedExit() (int, bool) { return t.exitCode, t.infrastructureFailure }
func (t *Transcript) EventBytes() []byte       { return append([]byte(nil), t.events...) }
func (t *Transcript) LogBytes() int64          { return t.logBytes }

// ReadStream drains one finite guest stream with shared log, event and frame
// limits. onLog receives untrusted bytes synchronously and must apply redaction
// before storage or live publication. It must not block beyond the job deadline.
// The owner must close/deadline reader on cancellation: a context alone cannot
// interrupt arbitrary io.Reader implementations. Any error discards the partial
// transcript; logs already delivered to the sink remain untrusted diagnostics.
func ReadStream(ctx context.Context, reader io.Reader, maximumLogBytes int64, onLog func(Kind, []byte) error) (*Transcript, error) {
	if ctx == nil || reader == nil || onLog == nil || maximumLogBytes < 1 || maximumLogBytes > MaximumLogBytes {
		return nil, ErrStream
	}
	t := &Transcript{}
	eventsStarted, outcomeSeen := false, false
	for frames := 0; ; frames++ {
		if ctx.Err() != nil {
			return nil, errors.Join(ErrStream, ctx.Err())
		}
		kind, raw, err := Read(reader)
		if err == io.EOF && outcomeSeen {
			if ctx.Err() != nil {
				return nil, errors.Join(ErrStream, ctx.Err())
			}
			return t, nil
		}
		if err != nil || outcomeSeen || frames >= MaximumFrames {
			return nil, errors.Join(ErrStream, err)
		}
		switch kind {
		case Stdout, Stderr:
			if eventsStarted || int64(len(raw)) > maximumLogBytes-t.logBytes {
				return nil, ErrStream
			}
			t.logBytes += int64(len(raw))
			if err := onLog(kind, raw); err != nil {
				return nil, errors.Join(ErrStream, err)
			}
		case Events:
			eventsStarted = true
			if len(raw) > MaximumEventBytes-len(t.events) {
				return nil, ErrStream
			}
			t.events = append(t.events, raw...)
		case Outcome:
			// Canonical encoding also rejects duplicate, absent and unknown fields,
			// coercion, trailing values and extra whitespace without loose defaults.
			if len(raw) > 64 {
				return nil, ErrStream
			}
			var claim struct {
				ExitCode              int  `json:"exitCode"`
				InfrastructureFailure bool `json:"infrastructureFailure"`
			}
			if json.Unmarshal(raw, &claim) != nil {
				return nil, ErrStream
			}
			canonical, err := json.Marshal(claim)
			if err != nil || !bytes.Equal(raw, canonical) || claim.ExitCode < 0 || claim.ExitCode > 255 || (claim.ExitCode == 125) != claim.InfrastructureFailure {
				return nil, ErrStream
			}
			t.exitCode, t.infrastructureFailure = claim.ExitCode, claim.InfrastructureFailure
			outcomeSeen = true
		default:
			return nil, ErrStream
		}
	}
}
