package process

import (
	"io"
	"strings"
	"sync"
	"unicode/utf8"
)

type outputCapture struct {
	mu        sync.Mutex
	limit     int64
	observed  int64
	stdout    []byte
	stderr    []byte
	truncated bool
}

type captureWriter struct {
	capture *outputCapture
	stdout  bool
}

func newOutputCapture(limit int64) *outputCapture {
	return &outputCapture{limit: limit}
}

func (c *outputCapture) writer(stdout bool) io.Writer {
	return &captureWriter{capture: c, stdout: stdout}
}

func (w *captureWriter) Write(data []byte) (int, error) {
	w.capture.mu.Lock()
	defer w.capture.mu.Unlock()

	w.capture.observed += int64(len(data))
	remaining := w.capture.limit - int64(len(w.capture.stdout)+len(w.capture.stderr))
	if remaining <= 0 {
		w.capture.truncated = w.capture.truncated || len(data) > 0
		return len(data), nil
	}

	writeLength := int64(len(data))
	if writeLength > remaining {
		writeLength = remaining
		w.capture.truncated = true
	}
	if w.stdout {
		w.capture.stdout = append(w.capture.stdout, data[:writeLength]...)
	} else {
		w.capture.stderr = append(w.capture.stderr, data[:writeLength]...)
	}
	return len(data), nil
}

func (c *outputCapture) collect() (stdout, stderr string, captured, observed int64, truncated bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stdout = normalizeOutput(c.stdout)
	stderr = normalizeOutput(c.stderr)
	captured = int64(len(c.stdout) + len(c.stderr))
	return stdout, stderr, captured, c.observed, c.truncated
}

func normalizeOutput(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	return strings.ToValidUTF8(string(data), "\uFFFD")
}
