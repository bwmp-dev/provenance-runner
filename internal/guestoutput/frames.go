// Package guestoutput frames untrusted guest output; framing grants no trust.
// Consumers must enforce total limits, validate event schemas and independently
// observe sandbox completion. A guest record is never runtime identity evidence.
package guestoutput

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

const MaximumChunk = 32 << 10

type Kind byte

const (
	Stdout Kind = iota + 1
	Stderr
	Events
	Outcome
)

var ErrFrame = errors.New("guest_output_frame_invalid")

type Encoder struct {
	mu     sync.Mutex
	output io.Writer
	failed bool
}

func NewEncoder(output io.Writer) *Encoder { return &Encoder{output: output} }
func (e *Encoder) Write(kind Kind, data []byte) error {
	if e == nil {
		return ErrFrame
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed || e.output == nil || kind < Stdout || kind > Outcome || len(data) == 0 || len(data) > MaximumChunk {
		e.failed = true
		return ErrFrame
	}
	var header [9]byte
	copy(header[:4], "PVG1")
	header[4] = byte(kind)
	binary.BigEndian.PutUint32(header[5:], uint32(len(data)))
	for _, part := range [][]byte{header[:], data} {
		n, err := e.output.Write(part)
		if err != nil || n != len(part) {
			e.failed = true
			return errors.Join(ErrFrame, err)
		}
	}
	return nil
}

func Read(reader io.Reader) (Kind, []byte, error) {
	if reader == nil {
		return 0, nil, ErrFrame
	}
	var header [9]byte
	n, err := io.ReadFull(reader, header[:])
	if err != nil {
		if n == 0 && err == io.EOF {
			return 0, nil, io.EOF
		}
		return 0, nil, errors.Join(ErrFrame, err)
	}
	kind := Kind(header[4])
	length := binary.BigEndian.Uint32(header[5:])
	if string(header[:4]) != "PVG1" || kind < Stdout || kind > Outcome || length == 0 || length > MaximumChunk {
		return 0, nil, ErrFrame
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(reader, data); err != nil {
		return 0, nil, errors.Join(ErrFrame, err)
	}
	return kind, data, nil
}
