//go:build linux

package measuredservice

import (
	"bytes"
	"io"
	"testing"
)

// Keep draining the existing 64-KiB service limit while retaining at most a
// 16-KiB prefix. This writer is never installed for real Paper or selected secrets.
type fixtureDiagnosticPrefix struct{ buffer bytes.Buffer }

func (p *fixtureDiagnosticPrefix) Len() int       { return p.buffer.Len() }
func (p *fixtureDiagnosticPrefix) String() string { return p.buffer.String() }
func (p *fixtureDiagnosticPrefix) Bytes() []byte  { return p.buffer.Bytes() }

func (p *fixtureDiagnosticPrefix) Write(value []byte) (int, error) {
	n := len(value)
	if remaining := (16 << 10) - p.Len(); remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = p.buffer.Write(value)
	}
	return n, nil
}

func TestFixtureDiagnosticPrefixRemainsBoundedWhileDraining(t *testing.T) {
	var writer fixtureDiagnosticPrefix
	first := bytes.Repeat([]byte("a"), 10<<10)
	second := bytes.Repeat([]byte("b"), 64<<10)
	for _, value := range [][]byte{first, second, second} {
		if n, err := io.Copy(&writer, io.LimitReader(bytes.NewReader(value), int64(len(value)))); err != nil || n != int64(len(value)) {
			t.Fatal("diagnostic drain changed")
		}
	}
	want := append(bytes.Clone(first), bytes.Repeat([]byte("b"), 6<<10)...)
	if !bytes.Equal(writer.Bytes(), want) {
		t.Fatal("diagnostic prefix not bounded")
	}
}
