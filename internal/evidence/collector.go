package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf8"
)

type Collector struct {
	mu                   sync.Mutex
	snapshotMu           sync.Mutex
	config               Config
	processors           map[Stream]*rawProcessor
	live                 boundedOutput
	complete             *archiveSpool
	events               []StructuredEvent
	eventBytes           int64
	rawObserved          int64
	truncatedLines       int64
	eventsTruncated      bool
	structuredEventError string
	closed               bool
	snapshot             *Bundle
	snapshotErr          error
	liveSink             func(LiveEntry)
}

// SetLiveSink replaces the optional non-blocking sink for sanitized lines.
// The sink is called synchronously and therefore must never wait on I/O.
func (c *Collector) SetLiveSink(sink func(LiveEntry)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.liveSink = sink
}

type rawTail struct {
	stream Stream
	bytes  int64
}

type boundedOutput struct {
	stdout    bytes.Buffer
	stderr    bytes.Buffer
	tail      []rawTail
	tailBytes int64
	captured  int64
	maximum   int64
	truncated bool
}

func NewCollector(config Config) (*Collector, error) {
	validated, err := config.withDefaults()
	if err != nil {
		return nil, fmt.Errorf("create evidence collector: %w", err)
	}
	complete, err := newArchiveSpool(validated.MaxCompleteLogBytes)
	if err != nil {
		return nil, fmt.Errorf("create evidence collector: %w", err)
	}
	collector := &Collector{
		config:     validated,
		processors: make(map[Stream]*rawProcessor, 2),
		events:     make([]StructuredEvent, 0, validated.MaxEvents),
		live:       boundedOutput{maximum: validated.MaxTotalBytes},
		complete:   complete,
	}
	collector.processors[StreamStdout] = newRawProcessor(collector, StreamStdout, validated)
	collector.processors[StreamStderr] = newRawProcessor(collector, StreamStderr, validated)
	return collector, nil
}

func (c *Collector) RawWriter(stream Stream) (io.Writer, error) {
	processor := c.processors[stream]
	if processor == nil {
		return nil, fmt.Errorf("create raw log writer: unsupported stream %q", stream)
	}
	return processor, nil
}

func (c *Collector) RecordEvent(ctx context.Context, input EventInput) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("record structured event: %w", err)
	}
	if err := validateEvent(input, c.config.MaxEventBytes); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("record structured event: collector is closed")
	}
	c.recordEventLocked(input)
	return nil
}

func (c *Collector) recordEventLocked(input EventInput) {
	if len(c.events) >= c.config.MaxEvents {
		c.eventsTruncated = true
		return
	}
	payload := append([]byte(nil), input.Payload...)
	c.events = append(c.events, StructuredEvent{
		Sequence: uint64(len(c.events) + 1),
		Kind:     input.Kind,
		Payload:  payload,
	})
	c.eventBytes += int64(len(payload))
}

func (c *Collector) Snapshot(ctx context.Context) (Bundle, error) {
	if err := ctx.Err(); err != nil {
		return Bundle{}, fmt.Errorf("snapshot evidence: %w", err)
	}
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	if c.snapshot != nil {
		return cloneBundle(*c.snapshot), c.snapshotErr
	}

	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.processors[StreamStdout].finish()
	c.processors[StreamStderr].finish()

	c.mu.Lock()
	stdout := c.live.stdout.String()
	stderr := c.live.stderr.String()
	events := append([]StructuredEvent(nil), c.events...)
	for index := range events {
		events[index].Payload = append([]byte(nil), events[index].Payload...)
	}
	usage := Usage{
		RawBytesObserved:     c.rawObserved,
		CapturedBytes:        c.live.captured,
		StructuredEventCount: int64(len(events)),
		StructuredEventBytes: c.eventBytes,
		TruncatedLineCount:   c.truncatedLines,
		OutputTruncated:      c.live.truncated || c.truncatedLines > 0,
		EventsTruncated:      c.eventsTruncated,
	}
	c.mu.Unlock()

	completeLog, archiveErr := c.complete.finalize(ctx)
	usage.CompleteLogBytes = completeLog.UncompressedBytes
	usage.CompressedLogBytes = completeLog.CompressedBytes
	usage.CompleteLogState = completeLog.State
	usage.CompleteLogTruncated = completeLog.Truncated
	bundle := Bundle{
		Stdout:               stdout,
		Stderr:               stderr,
		Events:               events,
		CompleteLog:          completeLog,
		Usage:                usage,
		StructuredEventError: c.structuredEventError,
	}
	c.snapshot = &bundle
	c.snapshotErr = archiveErr
	return cloneBundle(bundle), archiveErr
}

// Close releases any source spools left behind when collection could not run.
// A successfully finalized compressed archive is owned by the returned bundle
// and is intentionally not closed here.
func (c *Collector) Close() error {
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.snapshot == nil && c.complete != nil {
		c.complete.discardSources()
	}
	return nil
}

func (c *Collector) observeRawBytes(count int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rawObserved += count
	return c.live.truncated
}

func (c *Collector) emitRawLine(stream Stream, line []byte, lineTruncated, partial, redacted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if stream == StreamStdout && c.config.StructuredLinePrefix != "" && bytes.HasPrefix(line, []byte(c.config.StructuredLinePrefix)) {
		if lineTruncated {
			c.setStructuredEventError("structured event line exceeded the configured line limit")
			return
		}
		payload := bytes.TrimSuffix(line[len(c.config.StructuredLinePrefix):], []byte("\n"))
		payload = bytes.TrimSuffix(payload, []byte("\r"))
		input := EventInput{Kind: c.config.StructuredLineKind, Payload: json.RawMessage(payload)}
		if err := validateEvent(input, c.config.MaxEventBytes); err != nil {
			c.setStructuredEventError(err.Error())
			return
		}
		c.recordEventLocked(input)
		return
	}
	if rawContentLength(line) > c.config.MaxLineBytes {
		line = truncateRawLine(line, c.config.MaxLineBytes)
		lineTruncated = true
	}
	if lineTruncated {
		c.truncatedLines++
	}
	// The disk-spooled complete archive and bounded live projection deliberately
	// receive the same normalized, ANSI-free, redacted line.
	c.complete.append(stream, line)
	c.live.append(stream, line)
	if c.liveSink != nil {
		c.liveSink(LiveEntry{Stream: stream, Data: append([]byte(nil), line...), Partial: partial, Redacted: redacted})
	}
}

func rawContentLength(line []byte) int64 {
	content := bytes.TrimSuffix(line, []byte("\n"))
	return int64(len(bytes.TrimSuffix(content, []byte("\r"))))
}

func truncateRawLine(line []byte, maximum int64) []byte {
	newline := bytes.HasSuffix(line, []byte("\n"))
	content := bytes.TrimSuffix(line, []byte("\n"))
	content = bytes.TrimSuffix(content, []byte("\r"))
	content = content[:maximum]
	for len(content) > 0 && !utf8.Valid(content) {
		content = content[:len(content)-1]
	}
	output := make([]byte, 0, len(content)+len(LineTruncationMarker)+1)
	output = append(output, content...)
	output = append(output, LineTruncationMarker...)
	if newline {
		output = append(output, '\n')
	}
	return output
}

func (c *Collector) setStructuredEventError(message string) {
	if c.structuredEventError == "" {
		c.structuredEventError = message
	}
}

func (o *boundedOutput) append(stream Stream, content []byte) {
	if o.truncated {
		return
	}
	remaining := o.maximum - o.captured
	if int64(len(content)) > remaining {
		content = o.truncateTotal(content)
		o.truncated = true
	}
	if len(content) == 0 {
		return
	}
	o.captured += int64(len(content))
	o.appendStream(stream, content)
	o.trackTail(stream, int64(len(content)))
}

func (o *boundedOutput) truncateTotal(content []byte) []byte {
	marker := []byte(TotalTruncationMarker)
	if int64(len(marker)) > o.maximum {
		marker = marker[:o.maximum]
	}
	target := o.maximum - int64(len(marker))
	if o.captured > target {
		o.removeTail(o.captured - target)
	}
	remaining := target - o.captured
	prefix := content[:min(int(remaining), len(content))]
	for len(prefix) > 0 && !utf8.Valid(prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	result := make([]byte, 0, len(prefix)+len(marker))
	result = append(result, prefix...)
	result = append(result, marker...)
	return result
}

func (o *boundedOutput) appendStream(stream Stream, content []byte) {
	switch stream {
	case StreamStdout:
		_, _ = o.stdout.Write(content)
	case StreamStderr:
		_, _ = o.stderr.Write(content)
	}
}

func (o *boundedOutput) trackTail(stream Stream, count int64) {
	if count == 0 {
		return
	}
	o.tail = append(o.tail, rawTail{stream: stream, bytes: count})
	o.tailBytes += count
	maximum := int64(len(TotalTruncationMarker))
	for o.tailBytes > maximum && len(o.tail) > 0 {
		excess := o.tailBytes - maximum
		if o.tail[0].bytes <= excess {
			o.tailBytes -= o.tail[0].bytes
			o.tail = o.tail[1:]
			continue
		}
		o.tail[0].bytes -= excess
		o.tailBytes -= excess
	}
}

func (o *boundedOutput) removeTail(count int64) {
	for count > 0 && len(o.tail) > 0 {
		last := o.tail[len(o.tail)-1]
		remove := min(count, last.bytes)
		removed := o.truncateStream(last.stream, remove)
		o.captured -= removed
		count -= removed
		o.consumeTailMetadata(removed)
		if removed == 0 {
			return
		}
	}
}

func (o *boundedOutput) consumeTailMetadata(count int64) {
	for count > 0 && len(o.tail) > 0 {
		lastIndex := len(o.tail) - 1
		remove := min(count, o.tail[lastIndex].bytes)
		o.tail[lastIndex].bytes -= remove
		o.tailBytes -= remove
		count -= remove
		if o.tail[lastIndex].bytes == 0 {
			o.tail = o.tail[:lastIndex]
		}
	}
}

func (o *boundedOutput) truncateStream(stream Stream, count int64) int64 {
	var buffer *bytes.Buffer
	if stream == StreamStdout {
		buffer = &o.stdout
	} else {
		buffer = &o.stderr
	}
	originalLength := buffer.Len()
	newLength := max(0, originalLength-int(count))
	content := buffer.Bytes()[:newLength]
	for len(content) > 0 && !utf8.Valid(content) {
		content = content[:len(content)-1]
	}
	buffer.Truncate(len(content))
	return int64(originalLength - len(content))
}

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (w *contextWriter) Write(content []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.writer.Write(content)
}

func cloneBundle(bundle Bundle) Bundle {
	bundle.Events = append([]StructuredEvent(nil), bundle.Events...)
	for index := range bundle.Events {
		bundle.Events[index].Payload = append([]byte(nil), bundle.Events[index].Payload...)
	}
	return bundle
}
