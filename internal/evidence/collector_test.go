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
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestCollectorSeparatesStructuredEventsFromRawLogs(t *testing.T) {
	collector := newTestCollector(t, Config{})
	if err := collector.RecordEvent(context.Background(), EventInput{
		Kind:    "probe.lifecycle",
		Payload: json.RawMessage(`{"state":"enabled"}`),
	}); err != nil {
		t.Fatalf("RecordEvent() error = %v", err)
	}
	writeChunks(t, collector, StreamStdout, []byte("raw server log\n"))

	bundle := snapshot(t, collector)
	if bundle.Stdout != "raw server log\n" || bundle.Stderr != "" {
		t.Fatalf("stdout = %q, stderr = %q", bundle.Stdout, bundle.Stderr)
	}
	if len(bundle.Events) != 1 || bundle.Events[0].Kind != "probe.lifecycle" || string(bundle.Events[0].Payload) != `{"state":"enabled"}` {
		t.Fatalf("events = %#v", bundle.Events)
	}
	complete := decompress(t, bundle.CompleteLog)
	if !strings.Contains(complete, "raw server log") || strings.Contains(complete, "probe.lifecycle") || strings.Contains(complete, "enabled") {
		t.Fatalf("complete log = %q", complete)
	}
	if bundle.Usage.StructuredEventCount != 1 || bundle.Usage.CompleteLogBytes != bundle.CompleteLog.UncompressedBytes {
		t.Fatalf("usage = %#v, complete log = %#v", bundle.Usage, bundle.CompleteLog)
	}
	if bundle.Usage.StructuredEventBytes != int64(len(`{"state":"enabled"}`)) {
		t.Fatalf("structured event bytes = %d", bundle.Usage.StructuredEventBytes)
	}
	digest := sha256.Sum256(archiveBytes(t, bundle.CompleteLog))
	if bundle.CompleteLog.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("complete log SHA-256 = %q", bundle.CompleteLog.SHA256)
	}
}

func TestCollectorNormalizesUTF8AndRemovesSplitANSI(t *testing.T) {
	collector := newTestCollector(t, Config{MaxLineBytes: 256, MaxTotalBytes: 512})
	writer := rawWriter(t, collector, StreamStdout)
	chunks := [][]byte{
		[]byte("plain "),
		{0xe2},
		{0x98, 0x83},
		[]byte(" \x1b["),
		[]byte("31mred"),
		[]byte("\x1b]0;hidden"),
		[]byte(" title\x1b"),
		[]byte("\\"),
		[]byte("\x1b[0m invalid="),
		{0xff},
		{0xe2, 0x82},
		[]byte("\n"),
	}
	for _, chunk := range chunks {
		if _, err := writer.Write(chunk); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}

	bundle := snapshot(t, collector)
	want := "plain ☃ red invalid=��\n"
	if bundle.Stdout != want {
		t.Fatalf("stdout = %q, want %q", bundle.Stdout, want)
	}
	if strings.ContainsRune(bundle.Stdout, '\x1b') || !utf8.ValidString(bundle.Stdout) {
		t.Fatalf("stdout is not normalized ANSI-free UTF-8: %q", bundle.Stdout)
	}
}

func TestCollectorDoesNotLetMalformedANSIEscapesHideLineBoundaries(t *testing.T) {
	collector := newTestCollector(t, Config{})
	writeChunks(t, collector, StreamStdout, []byte("first\x1b[31\nsecond\x1b\nthird\n"))
	bundle := snapshot(t, collector)
	if bundle.Stdout != "first\nsecond\nthird\n" {
		t.Fatalf("stdout = %q", bundle.Stdout)
	}
}

func TestCollectorRedactsSecretsAcrossChunks(t *testing.T) {
	collector := newTestCollector(t, Config{
		MaxLineBytes:  256,
		MaxTotalBytes: 512,
		Secrets:       []string{"token", "token-123", "pässword"},
	})
	writer := rawWriter(t, collector, StreamStdout)
	for _, chunk := range [][]byte{
		[]byte("first=tok"),
		[]byte("en-123 second=to"),
		[]byte("ken third=pä"),
		[]byte("ssword\n"),
	} {
		if _, err := writer.Write(chunk); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}

	bundle := snapshot(t, collector)
	want := "first=[REDACTED] second=[REDACTED] third=[REDACTED]\n"
	if bundle.Stdout != want {
		t.Fatalf("stdout = %q, want %q", bundle.Stdout, want)
	}
	complete := decompress(t, bundle.CompleteLog)
	for _, secret := range []string{"token", "token-123", "pässword"} {
		if strings.Contains(complete, secret) {
			t.Fatalf("complete log contains secret %q: %q", secret, complete)
		}
	}
}

func TestCollectorRedactsSecretAtEveryChunkBoundary(t *testing.T) {
	input := []byte("prefix token-123 suffix\n")
	for split := 0; split <= len(input); split++ {
		t.Run(fmt.Sprintf("split-%d", split), func(t *testing.T) {
			collector := newTestCollector(t, Config{Secrets: []string{"token-123"}})
			writeChunks(t, collector, StreamStdout, input[:split], input[split:])
			bundle := snapshot(t, collector)
			if bundle.Stdout != "prefix [REDACTED] suffix\n" {
				t.Fatalf("stdout = %q", bundle.Stdout)
			}
		})
	}
}

func TestCollectorCapsLongLinesWithMarker(t *testing.T) {
	collector := newTestCollector(t, Config{MaxLineBytes: 8, MaxTotalBytes: 256})
	writeChunks(t, collector, StreamStdout, []byte("abcdefghijklmnop\nok\n"))

	bundle := snapshot(t, collector)
	want := "abcdefgh" + LineTruncationMarker + "\nok\n"
	if bundle.Stdout != want {
		t.Fatalf("stdout = %q, want %q", bundle.Stdout, want)
	}
	if bundle.Usage.TruncatedLineCount != 1 || !bundle.Usage.OutputTruncated {
		t.Fatalf("usage = %#v", bundle.Usage)
	}
}

func TestCollectorCapsOutputFloodWithMarker(t *testing.T) {
	const maximum int64 = 64
	collector := newTestCollector(t, Config{MaxLineBytes: maximum, MaxTotalBytes: maximum})
	stdout := rawWriter(t, collector, StreamStdout)
	stderr := rawWriter(t, collector, StreamStderr)
	for range 1_000 {
		if _, err := stdout.Write([]byte("stdout flood\n")); err != nil {
			t.Fatalf("stdout Write() error = %v", err)
		}
		if _, err := stderr.Write([]byte("stderr flood\n")); err != nil {
			t.Fatalf("stderr Write() error = %v", err)
		}
	}

	bundle := snapshot(t, collector)
	captured := int64(len(bundle.Stdout) + len(bundle.Stderr))
	if captured != maximum || bundle.Usage.CapturedBytes != maximum {
		t.Fatalf("captured bytes = %d, usage = %#v", captured, bundle.Usage)
	}
	if !strings.Contains(bundle.Stdout+bundle.Stderr, TotalTruncationMarker) {
		t.Fatalf("bounded output does not contain truncation marker: stdout=%q stderr=%q", bundle.Stdout, bundle.Stderr)
	}
	if bundle.Usage.RawBytesObserved <= bundle.Usage.CapturedBytes || !bundle.Usage.OutputTruncated {
		t.Fatalf("usage = %#v", bundle.Usage)
	}
	complete := decompress(t, bundle.CompleteLog)
	if strings.Count(complete, "stdout flood\n") != 1_000 || strings.Count(complete, "stderr flood\n") != 1_000 {
		t.Fatalf("complete log did not retain the output flood: %d bytes", len(complete))
	}
	if strings.Contains(complete, TotalTruncationMarker) || bundle.Usage.CompleteLogBytes <= bundle.Usage.CapturedBytes {
		t.Fatalf("complete log was bounded by the live limit: usage=%#v", bundle.Usage)
	}
}

func TestCollectorStreamsCompleteArchiveBeyondFormer16MiBBoundary(t *testing.T) {
	const payloadBytes = 17 << 20
	line := append(bytes.Repeat([]byte{'x'}, 4095), '\n')
	collector := newTestCollector(t, Config{MaxLineBytes: 4095, MaxTotalBytes: 64 << 10})
	stdout := rawWriter(t, collector, StreamStdout)
	wantDigest := sha256.New()
	_, _ = wantDigest.Write([]byte("[stdout]\n"))
	for written := 0; written < payloadBytes; written += len(line) {
		if _, err := stdout.Write(line); err != nil {
			t.Fatal(err)
		}
		_, _ = wantDigest.Write(line)
	}

	bundle := snapshot(t, collector)
	if bundle.CompleteLog.State != CompleteLogStateComplete || bundle.CompleteLog.Truncated || bundle.CompleteLog.UncompressedBytes != payloadBytes+int64(len("[stdout]\n")) {
		t.Fatalf("complete log = %#v", bundle.CompleteLog)
	}
	if collector.live.captured != 64<<10 || collector.complete.stdoutBytes != payloadBytes {
		t.Fatalf("live/archive retention = %d/%d", collector.live.captured, collector.complete.stdoutBytes)
	}
	reader, err := gzip.NewReader(io.NewSectionReader(bundle.CompleteLog.Archive, 0, bundle.CompleteLog.CompressedBytes))
	if err != nil {
		t.Fatal(err)
	}
	gotDigest := sha256.New()
	gotBytes, copyErr := io.Copy(gotDigest, reader)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal(errors.Join(copyErr, closeErr))
	}
	if gotBytes != bundle.CompleteLog.UncompressedBytes || !bytes.Equal(gotDigest.Sum(nil), wantDigest.Sum(nil)) {
		t.Fatalf("entire archive mismatch: bytes=%d sha256=%x, want bytes=%d sha256=%x", gotBytes, gotDigest.Sum(nil), bundle.CompleteLog.UncompressedBytes, wantDigest.Sum(nil))
	}
}

func TestCollectorFailsClosedAtCompleteLogOperationalBoundary(t *testing.T) {
	collector := newTestCollector(t, Config{MaxLineBytes: 32, MaxTotalBytes: 32, MaxCompleteLogBytes: 64})
	for range 100 {
		writeChunks(t, collector, StreamStdout, []byte("complete archive flood\n"))
	}

	bundle, err := collector.Snapshot(context.Background())
	if err == nil || !strings.Contains(err.Error(), "operational retention boundary") {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if bundle.CompleteLog.State != CompleteLogStateTruncated || !bundle.CompleteLog.Truncated || bundle.CompleteLog.Archive != nil || !bundle.Usage.CompleteLogTruncated {
		t.Fatalf("complete-log boundary state = %#v, usage = %#v", bundle.CompleteLog, bundle.Usage)
	}
	if second, secondErr := collector.Snapshot(context.Background()); secondErr == nil || second.CompleteLog.State != CompleteLogStateTruncated {
		t.Fatalf("second Snapshot() = %#v, %v", second.CompleteLog, secondErr)
	}
}

func TestCollectorFailsClosedWhenCompleteLogSpoolWriteFails(t *testing.T) {
	collector := newTestCollector(t, Config{})
	if err := collector.complete.stdout.Close(); err != nil {
		t.Fatal(err)
	}
	writeChunks(t, collector, StreamStdout, []byte("retention must fail\n"))
	bundle, err := collector.Snapshot(context.Background())
	if err == nil || !strings.Contains(err.Error(), "spool complete log") {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if bundle.CompleteLog.State != CompleteLogStateFailed || bundle.CompleteLog.Truncated || bundle.CompleteLog.Archive != nil || bundle.CompleteLog.Error == "" {
		t.Fatalf("complete-log failure state = %#v", bundle.CompleteLog)
	}
}

func TestCollectorKeepsTruncatedMultibyteOutputValid(t *testing.T) {
	collector := newTestCollector(t, Config{MaxLineBytes: 32, MaxTotalBytes: 32})
	writeChunks(t, collector, StreamStdout, []byte(strings.Repeat("界", 30)))
	bundle := snapshot(t, collector)
	if !utf8.ValidString(bundle.Stdout) || int64(len(bundle.Stdout)) > 32 {
		t.Fatalf("stdout is not valid bounded UTF-8: %q (%d bytes)", bundle.Stdout, len(bundle.Stdout))
	}
	if !strings.Contains(bundle.Stdout, TotalTruncationMarker) || !bundle.Usage.OutputTruncated {
		t.Fatalf("stdout = %q, usage = %#v", bundle.Stdout, bundle.Usage)
	}
}

func TestCollectorCancellationAndSnapshotIdempotence(t *testing.T) {
	collector := newTestCollector(t, Config{})
	writeChunks(t, collector, StreamStdout, []byte("before\n"))
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := collector.RecordEvent(cancelled, EventInput{Kind: "event", Payload: json.RawMessage(`{}`)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("RecordEvent() error = %v, want context canceled", err)
	}
	if _, err := collector.Snapshot(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Snapshot() error = %v, want context canceled", err)
	}

	first := snapshot(t, collector)
	writer := rawWriter(t, collector, StreamStdout)
	if written, err := writer.Write([]byte("after\n")); err != nil || written != len("after\n") {
		t.Fatalf("Write() after snapshot = %d, %v", written, err)
	}
	second := snapshot(t, collector)
	if first.Stdout != second.Stdout || first.CompleteLog.SHA256 != second.CompleteLog.SHA256 || first.CompleteLog.Archive != second.CompleteLog.Archive {
		t.Fatalf("snapshots differ: first=%#v second=%#v", first, second)
	}
}

func TestCollectorBoundsStructuredEventsIndependently(t *testing.T) {
	collector := newTestCollector(t, Config{MaxEvents: 1, MaxEventBytes: 8})
	if err := collector.RecordEvent(context.Background(), EventInput{Kind: "first", Payload: json.RawMessage(`{"a":1}`)}); err != nil {
		t.Fatalf("RecordEvent(first) error = %v", err)
	}
	if err := collector.RecordEvent(context.Background(), EventInput{Kind: "second", Payload: json.RawMessage(`{"b":2}`)}); err != nil {
		t.Fatalf("RecordEvent(second) error = %v", err)
	}
	if err := collector.RecordEvent(context.Background(), EventInput{Kind: "invalid", Payload: json.RawMessage(`{`)}); err == nil {
		t.Fatal("RecordEvent(invalid) error = nil")
	}
	writeChunks(t, collector, StreamStderr, []byte("raw\n"))

	bundle := snapshot(t, collector)
	if len(bundle.Events) != 1 || !bundle.Usage.EventsTruncated || bundle.Stderr != "raw\n" {
		t.Fatalf("bundle = %#v", bundle)
	}
}

func TestCollectorExtractsBoundedStructuredLinesAfterRawOutputTruncation(t *testing.T) {
	collector, err := NewCollector(Config{
		MaxLineBytes:         8,
		MaxTotalBytes:        8,
		StructuredLinePrefix: "EVENT:",
		StructuredLineKind:   "probe",
	})
	if err != nil {
		t.Fatal(err)
	}
	stdout, _ := collector.RawWriter(StreamStdout)
	_, _ = io.WriteString(stdout, "raw output that fills the capture\nEVENT:{\"ok\":true}\n")
	bundle, err := collector.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Events) != 1 || bundle.Events[0].Kind != "probe" || string(bundle.Events[0].Payload) != `{"ok":true}` {
		t.Fatalf("events = %#v", bundle.Events)
	}
	if !bundle.Usage.OutputTruncated {
		t.Error("raw output was not marked truncated")
	}
}

func TestCollectorReportsMalformedStructuredLine(t *testing.T) {
	collector, err := NewCollector(Config{StructuredLinePrefix: "EVENT:", StructuredLineKind: "probe"})
	if err != nil {
		t.Fatal(err)
	}
	stdout, _ := collector.RawWriter(StreamStdout)
	_, _ = io.WriteString(stdout, "EVENT:not-json\n")
	bundle, err := collector.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.StructuredEventError == "" || len(bundle.Events) != 0 {
		t.Fatalf("bundle event error/events = %q/%#v", bundle.StructuredEventError, bundle.Events)
	}
}

func TestCollectorAcceptsConcurrentRawStreams(t *testing.T) {
	collector := newTestCollector(t, Config{MaxLineBytes: 128, MaxTotalBytes: 1 << 20})
	stdout := rawWriter(t, collector, StreamStdout)
	stderr := rawWriter(t, collector, StreamStderr)
	const writes = 200
	var wait sync.WaitGroup
	for _, writer := range []io.Writer{stdout, stderr} {
		wait.Add(1)
		go func(writer io.Writer) {
			defer wait.Done()
			for range writes {
				if _, err := writer.Write([]byte("concurrent output\n")); err != nil {
					t.Errorf("Write() error = %v", err)
					return
				}
			}
		}(writer)
	}
	wait.Wait()
	bundle := snapshot(t, collector)
	wantObserved := int64(2 * writes * len("concurrent output\n"))
	if bundle.Usage.RawBytesObserved != wantObserved || bundle.Usage.OutputTruncated {
		t.Fatalf("usage = %#v, want observed %d", bundle.Usage, wantObserved)
	}
}

func TestCollectorRejectsUnsafeConfiguration(t *testing.T) {
	tests := []Config{
		{MaxTotalBytes: MaximumTotalBytes + 1},
		{MaxCompleteLogBytes: MaximumCompleteLogBytes + 1},
		{MaxLineBytes: MaximumLineBytes + 1, MaxTotalBytes: MaximumTotalBytes},
		{MaxEvents: MaximumEvents + 1},
		{MaxEventBytes: MaximumEventBytes + 1},
		{Secrets: []string{""}},
		{Secrets: []string{string([]byte{0xff})}},
	}
	for _, config := range tests {
		if _, err := NewCollector(config); err == nil {
			t.Fatalf("NewCollector(%#v) error = nil", config)
		}
	}
}

func newTestCollector(t *testing.T, config Config) *Collector {
	t.Helper()
	collector, err := NewCollector(config)
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}
	return collector
}

func rawWriter(t *testing.T, collector *Collector, stream Stream) io.Writer {
	t.Helper()
	writer, err := collector.RawWriter(stream)
	if err != nil {
		t.Fatalf("RawWriter() error = %v", err)
	}
	return writer
}

func writeChunks(t *testing.T, collector *Collector, stream Stream, chunks ...[]byte) {
	t.Helper()
	writer := rawWriter(t, collector, stream)
	for _, chunk := range chunks {
		if _, err := writer.Write(chunk); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
}

func snapshot(t *testing.T, collector *Collector) Bundle {
	t.Helper()
	bundle, err := collector.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if bundle.CompleteLog.Archive != nil {
		t.Cleanup(func() { _ = bundle.CompleteLog.Archive.Close() })
	}
	return bundle
}

func archiveBytes(t *testing.T, completeLog CompleteLog) []byte {
	t.Helper()
	if completeLog.Archive == nil {
		t.Fatalf("complete log archive is unavailable: %#v", completeLog)
	}
	content := make([]byte, completeLog.CompressedBytes)
	if _, err := completeLog.Archive.ReadAt(content, 0); err != nil {
		t.Fatalf("ReadAt() error = %v", err)
	}
	return content
}

func decompress(t *testing.T, completeLog CompleteLog) string {
	t.Helper()
	content := archiveBytes(t, completeLog)
	reader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("gzip.NewReader() error = %v", err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return string(decompressed)
}
