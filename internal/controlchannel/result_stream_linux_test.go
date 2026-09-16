//go:build linux

package controlchannel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/guestoutput"
	"golang.org/x/sys/unix"
)

// Pipes and sequenced packets need not preserve the guest encoder's writes.
// Exercise every split, including inside headers, with quiet-period keepalives.
func TestResultStreamPreservesGuestFramesAcrossEveryPacketSplit(t *testing.T) {
	const logs = "ROOT_SERVICE_STARTED\nfixture-padding-fixture-padding-\nROOT_SERVICE_OK\n"
	var encoded bytes.Buffer
	encoder := guestoutput.NewEncoder(&encoded)
	for _, frame := range []struct {
		kind guestoutput.Kind
		raw  string
	}{{guestoutput.Stdout, logs}, {guestoutput.Events, "{\"fixture\":true}\n"}, {guestoutput.Outcome, "{\"exitCode\":0,\"infrastructureFailure\":false}"}} {
		if err := encoder.Write(frame.kind, []byte(frame.raw)); err != nil {
			t.Fatal(err)
		}
	}
	completion, err := EncodeCompletion(0, false)
	if err != nil {
		t.Fatal(err)
	}
	raw := encoded.Bytes()
	for split := 1; split < len(raw); split++ {
		t.Run(strconv.Itoa(split), func(t *testing.T) {
			stream := resultParserFixture(t, []Packet{{Kind: Result}, {Kind: Result, Payload: raw[:split]}, {Kind: Result}, {Kind: Result, Payload: raw[split:]}, {Kind: Result}, {Kind: Completion, Payload: completion}})
			var observed bytes.Buffer
			transcript, err := guestoutput.ReadStream(context.Background(), stream, 1024, func(kind guestoutput.Kind, data []byte) error {
				if kind != guestoutput.Stdout {
					t.Fatal("unexpected stream")
				}
				_, err := observed.Write(data)
				return err
			})
			if err != nil || transcript == nil || observed.String() != logs || string(transcript.EventBytes()) != "{\"fixture\":true}\n" {
				t.Fatal("fragmented guest stream", err)
			}
			if _, err := stream.Receipt(); err != nil {
				t.Fatal("missing retirement receipt", err)
			}
		})
	}
}

// This fixture directly exercises the private parser with same-user sockets.
// It does not test or claim authenticated root provenance; production callers
// cannot construct ResultStream fields and must use NewResultStream.
func resultParserFixture(t *testing.T, packets []Packet) *ResultStream {
	t.Helper()
	a, b := pair(t, unix.SOCK_SEQPACKET)
	reader, err := New(a, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	writer, err := New(b, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	r := &ResultStream{channel: reader, ctx: context.Background()}
	t.Cleanup(func() { r.Close(); writer.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer writer.Close()
		for i, p := range packets {
			p.Sequence = uint64(i + 1)
			if writer.Send(p, time.Now().Add(time.Second)) != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { writer.Close(); <-done })
	return r
}

func TestResultStreamRequiresRetirementRatherThanSocketEOF(t *testing.T) {
	completion, err := EncodeCompletion(0, false)
	if err != nil {
		t.Fatal(err)
	}
	r := resultParserFixture(t, []Packet{{Kind: Result, Payload: []byte("one")}, {Kind: Result}, {Kind: Result, Payload: []byte("two")}, {Kind: Completion, Payload: completion}})
	if _, err := r.Receipt(); err == nil {
		t.Fatal("premature receipt")
	}
	raw, err := io.ReadAll(r)
	if err != nil || string(raw) != "onetwo" {
		t.Fatal("stream", err)
	}
	receipt, err := r.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	exit, infra, err := receipt.Outcome()
	if err != nil || exit != 0 || infra {
		t.Fatal("completion")
	}
	encoded, _ := json.Marshal(receipt)
	var forged RootCompletion
	if json.Unmarshal(encoded, &forged) != nil {
		t.Fatal("JSON")
	}
	if _, _, err := forged.Outcome(); err == nil {
		t.Fatal("JSON recreated receipt")
	}
	r = resultParserFixture(t, []Packet{{Kind: Result, Payload: []byte("partial")}})
	if _, err := io.ReadAll(r); err == nil || !errors.Is(err, ErrChannel) {
		t.Fatal("EOF became completion", err)
	}
	if _, err := r.Receipt(); err == nil {
		t.Fatal("failed stream retained receipt")
	}
}

func TestResultStreamRefusesWrongPhaseAndBounds(t *testing.T) {
	valid, _ := EncodeCompletion(125, true)
	for name, packet := range map[string]Packet{
		"observation": {Kind: Observation, Payload: []byte("wrong phase")},
		"short":       {Kind: Completion, Payload: valid[:7]},
		"unknown":     {Kind: Completion, Payload: []byte("PVCR\x01\x00\x02\x00")},
		"reserved":    {Kind: Completion, Payload: []byte("PVCR\x01\x00\x00\x01")},
	} {
		t.Run(name, func(t *testing.T) {
			r := resultParserFixture(t, []Packet{packet})
			if _, err := io.ReadAll(r); err == nil {
				t.Fatal("invalid phase accepted")
			}
		})
	}
	r := resultParserFixture(t, []Packet{{Kind: Result, Payload: []byte("xx")}})
	r.bytes = MaximumResultBytes - 1
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("byte bound")
	}
	r = resultParserFixture(t, []Packet{{Kind: Result}})
	r.packets = MaximumResultPackets
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("packet bound")
	}
	if _, err := EncodeCompletion(-1, false); err == nil {
		t.Fatal("negative exit")
	}
	if _, err := EncodeCompletion(256, false); err == nil {
		t.Fatal("overflow exit")
	}
}

func TestResultStreamRefusesNonRootConstructorAndCancelledContext(t *testing.T) {
	var zero ResultStream
	if _, err := zero.Read(make([]byte, 1)); err == nil {
		t.Fatal("zero stream accepted")
	}
	if _, err := zero.Receipt(); err == nil {
		t.Fatal("zero receipt accepted")
	}
	if zero.Close() != nil {
		t.Fatal("zero close")
	}
	a, _ := pair(t, unix.SOCK_SEQPACKET)
	channel, err := New(a, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewResultStream(ctx, channel); err == nil {
		t.Fatal("cancelled context")
	}
	if os.Getuid() != 0 {
		if _, err := NewResultStream(context.Background(), channel); err == nil {
			t.Fatal("non-root peer")
		}
	}
}

func TestResultStreamCancellationInterruptsBlockedSocket(t *testing.T) {
	a, b := pair(t, unix.SOCK_SEQPACKET)
	channel, err := New(a, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	r := &ResultStream{channel: channel, ctx: ctx}
	r.stop = context.AfterFunc(ctx, func() { channel.Close() })
	defer r.Close()
	done := make(chan error, 1)
	go func() { _, err := r.Read(make([]byte, 1)); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close owned socket")
	}
}
