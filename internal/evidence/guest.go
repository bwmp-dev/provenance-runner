package evidence

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/bwmp-dev/provenance-runner/internal/guestoutput"
)

// ConsumeGuest accepts one framed stream into this collector's existing
// streaming redaction and complete-log path. Stdout is never an event channel.
// Event payloads must subsequently pass the provider's lifecycle validator.
// The returned transcript remains untrusted and cannot establish actual exit,
// sandbox retirement or runtime identity. On failure Snapshot may still provide
// sanitized diagnostics, but no partial transcript is returned as a job result.
// The owner must close/deadline the reader when the execution context ends.
func (c *Collector) ConsumeGuest(ctx context.Context, reader io.Reader, maximumLogBytes int64) (accepted *guestoutput.Transcript, result error) {
	if c == nil || ctx == nil || ctx.Err() != nil || reader == nil {
		return nil, guestoutput.ErrStream
	}
	c.mu.Lock()
	if c.closed || c.guestConsumed || c.config.StructuredLinePrefix != "" || c.rawObserved != 0 || len(c.events) != 0 {
		c.mu.Unlock()
		return nil, guestoutput.ErrStream
	}
	c.guestConsumed = true
	c.mu.Unlock()
	defer func() {
		if result != nil {
			c.mu.Lock()
			c.setStructuredEventError("measured guest output refused")
			c.mu.Unlock()
		}
	}()
	stdout, _ := c.RawWriter(StreamStdout)
	stderr, _ := c.RawWriter(StreamStderr)
	transcript, err := guestoutput.ReadStream(ctx, reader, maximumLogBytes, func(kind guestoutput.Kind, raw []byte) error {
		writer := stdout
		if kind == guestoutput.Stderr {
			writer = stderr
		}
		n, err := writer.Write(raw)
		if n != len(raw) {
			return errors.Join(err, io.ErrShortWrite)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	raw := transcript.EventBytes()
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		return nil, guestoutput.ErrStream
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), int(c.config.MaxEventBytes)+2)
	count := 0
	for scanner.Scan() {
		count++
		if count > c.config.MaxEvents || len(scanner.Bytes()) == 0 {
			return nil, guestoutput.ErrStream
		}
		if err := c.RecordEvent(ctx, EventInput{Kind: "probe", Payload: scanner.Bytes()}); err != nil {
			return nil, guestoutput.ErrStream
		}
		c.mu.Lock()
		invalid := c.structuredEventError != "" || c.eventsTruncated || c.closed
		c.mu.Unlock()
		if invalid {
			return nil, guestoutput.ErrStream
		}
	}
	if scanner.Err() != nil || ctx.Err() != nil {
		return nil, errors.Join(guestoutput.ErrStream, ctx.Err())
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, guestoutput.ErrStream
	}
	return transcript, nil
}
