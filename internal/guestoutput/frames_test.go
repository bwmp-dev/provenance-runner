package guestoutput

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
)

func TestConcurrentFramesRemainWhole(t *testing.T) {
	var output bytes.Buffer
	e := NewEncoder(&output)
	var wg sync.WaitGroup
	for _, kind := range []Kind{Stdout, Stderr} {
		wg.Add(1)
		go func(k Kind) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if e.Write(k, bytes.Repeat([]byte{byte(k)}, 100)) != nil {
					t.Error("write failed")
				}
			}
		}(kind)
	}
	wg.Wait()
	for i := 0; i < 40; i++ {
		kind, data, err := Read(&output)
		if err != nil || len(data) != 100 || !bytes.Equal(data, bytes.Repeat([]byte{byte(kind)}, 100)) {
			t.Fatal("interleaved frame", err)
		}
	}
	if _, _, err := Read(&output); err != io.EOF {
		t.Fatal("missing EOF")
	}
}
func TestMalformedFrameAndFailedEncoderRefuse(t *testing.T) {
	for _, raw := range [][]byte{[]byte("PVG1"), []byte("bad-magic"), append([]byte("PVG1\x01"), []byte{255, 255, 255, 255}...), append([]byte("PVG1\x09"), []byte{0, 0, 0, 1}...)} {
		if _, _, err := Read(bytes.NewReader(raw)); !errors.Is(err, ErrFrame) {
			t.Fatal("malformed frame accepted")
		}
	}
	var header [9]byte
	copy(header[:], "PVG1")
	header[4] = byte(Stdout)
	binary.BigEndian.PutUint32(header[5:], 1)
	if _, _, err := Read(bytes.NewReader(header[:])); !errors.Is(err, ErrFrame) {
		t.Fatal("truncated payload")
	}
	var output bytes.Buffer
	e := NewEncoder(&output)
	if e.Write(Stdout, make([]byte, MaximumChunk+1)) == nil || e.Write(Stdout, []byte("resume")) == nil {
		t.Fatal("failed encoder resumed")
	}
}
