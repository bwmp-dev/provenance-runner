package evidence

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	stdout               bytes.Buffer
	stderr               bytes.Buffer
	tail                 []rawTail
	tailBytes            int64
	events               []StructuredEvent
	eventBytes           int64
	rawObserved          int64
	captured             int64
	truncatedLines       int64
	totalTruncated       bool
	eventsTruncated      bool
	structuredEventError string
	closed               bool
	snapshot             *Bundle
}

type rawTail struct {
	stream Stream
	bytes  int64
}

func NewCollector(config Config) (*Collector, error) {
	validated, err := config.withDefaults()
	if err != nil {
		return nil, fmt.Errorf("create evidence collector: %w", err)
	}
	collector := &Collector{
		config:     validated,
		processors: make(map[Stream]*rawProcessor, 2),
		events:     make([]StructuredEvent, 0, validated.MaxEvents),
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
		return cloneBundle(*c.snapshot), nil
	}

	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.processors[StreamStdout].finish()
	c.processors[StreamStderr].finish()

	c.mu.Lock()
	stdout := c.stdout.String()
	stderr := c.stderr.String()
	complete := completeLogContent(c.stdout.Bytes(), c.stderr.Bytes())
	events := append([]StructuredEvent(nil), c.events...)
	for index := range events {
		events[index].Payload = append([]byte(nil), events[index].Payload...)
	}
	usage := Usage{
		RawBytesObserved:     c.rawObserved,
		CapturedBytes:        c.captured,
		StructuredEventCount: int64(len(events)),
		StructuredEventBytes: c.eventBytes,
		TruncatedLineCount:   c.truncatedLines,
		OutputTruncated:      c.totalTruncated || c.truncatedLines > 0,
		EventsTruncated:      c.eventsTruncated,
	}
	c.mu.Unlock()

	compressed, err := compressCompleteLog(ctx, complete)
	if err != nil {
		return Bundle{}, err
	}
	digest := sha256.Sum256(compressed)
	usage.CompleteLogBytes = int64(len(complete))
	usage.CompressedLogBytes = int64(len(compressed))
	bundle := Bundle{
		Stdout: stdout,
		Stderr: stderr,
		Events: events,
		CompleteLog: CompleteLog{
			ContentType:       "text/plain; charset=utf-8",
			ContentEncoding:   "gzip",
			SHA256:            hex.EncodeToString(digest[:]),
			UncompressedBytes: int64(len(complete)),
			CompressedBytes:   int64(len(compressed)),
			Data:              compressed,
		},
		Usage:                usage,
		StructuredEventError: c.structuredEventError,
	}
	c.snapshot = &bundle
	return cloneBundle(bundle), nil
}

func (c *Collector) observeRawBytes(count int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rawObserved += count
	return c.totalTruncated
}

func (c *Collector) emitRawLine(stream Stream, line []byte, lineTruncated bool) {
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
	if c.totalTruncated {
		return
	}
	remaining := c.config.MaxTotalBytes - c.captured
	if int64(len(line)) > remaining {
		line = c.truncateTotal(line)
		c.totalTruncated = true
	}
	if len(line) == 0 {
		return
	}
	c.captured += int64(len(line))
	c.appendStream(stream, line)
	c.trackTail(stream, int64(len(line)))
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

func (c *Collector) truncateTotal(content []byte) []byte {
	marker := []byte(TotalTruncationMarker)
	if int64(len(marker)) > c.config.MaxTotalBytes {
		marker = marker[:c.config.MaxTotalBytes]
	}
	target := c.config.MaxTotalBytes - int64(len(marker))
	if c.captured > target {
		c.removeTail(c.captured - target)
	}
	remaining := target - c.captured
	prefix := content[:min(int(remaining), len(content))]
	for len(prefix) > 0 && !utf8.Valid(prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	result := make([]byte, 0, len(prefix)+len(marker))
	result = append(result, prefix...)
	result = append(result, marker...)
	return result
}

func (c *Collector) appendStream(stream Stream, content []byte) {
	switch stream {
	case StreamStdout:
		_, _ = c.stdout.Write(content)
	case StreamStderr:
		_, _ = c.stderr.Write(content)
	}
}

func (c *Collector) trackTail(stream Stream, count int64) {
	if count == 0 {
		return
	}
	c.tail = append(c.tail, rawTail{stream: stream, bytes: count})
	c.tailBytes += count
	maximum := int64(len(TotalTruncationMarker))
	for c.tailBytes > maximum && len(c.tail) > 0 {
		excess := c.tailBytes - maximum
		if c.tail[0].bytes <= excess {
			c.tailBytes -= c.tail[0].bytes
			c.tail = c.tail[1:]
			continue
		}
		c.tail[0].bytes -= excess
		c.tailBytes -= excess
	}
}

func (c *Collector) removeTail(count int64) {
	for count > 0 && len(c.tail) > 0 {
		last := c.tail[len(c.tail)-1]
		remove := min(count, last.bytes)
		removed := c.truncateStream(last.stream, remove)
		c.captured -= removed
		count -= removed
		c.consumeTailMetadata(removed)
		if removed == 0 {
			return
		}
	}
}

func (c *Collector) consumeTailMetadata(count int64) {
	for count > 0 && len(c.tail) > 0 {
		lastIndex := len(c.tail) - 1
		remove := min(count, c.tail[lastIndex].bytes)
		c.tail[lastIndex].bytes -= remove
		c.tailBytes -= remove
		count -= remove
		if c.tail[lastIndex].bytes == 0 {
			c.tail = c.tail[:lastIndex]
		}
	}
}

func (c *Collector) truncateStream(stream Stream, count int64) int64 {
	var buffer *bytes.Buffer
	if stream == StreamStdout {
		buffer = &c.stdout
	} else {
		buffer = &c.stderr
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

func completeLogContent(stdout, stderr []byte) []byte {
	var complete bytes.Buffer
	appendStream := func(name string, content []byte) {
		if len(content) == 0 {
			return
		}
		_, _ = fmt.Fprintf(&complete, "[%s]\n", name)
		_, _ = complete.Write(content)
		if content[len(content)-1] != '\n' {
			_ = complete.WriteByte('\n')
		}
	}
	appendStream(string(StreamStdout), stdout)
	appendStream(string(StreamStderr), stderr)
	return complete.Bytes()
}

func compressCompleteLog(ctx context.Context, content []byte) ([]byte, error) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&contextWriter{ctx: ctx, writer: &compressed})
	if _, err := writer.Write(content); err != nil {
		writer.Close()
		return nil, fmt.Errorf("compress complete log: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("compress complete log: %w", err)
	}
	return compressed.Bytes(), nil
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
	bundle.CompleteLog.Data = append([]byte(nil), bundle.CompleteLog.Data...)
	return bundle
}
