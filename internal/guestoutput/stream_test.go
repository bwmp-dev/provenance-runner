package guestoutput

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

const goodOutcome = `{"exitCode":0,"infrastructureFailure":false}`

type streamFrame struct {
	kind Kind
	data string
}

func streamBytes(t *testing.T, frames ...streamFrame) []byte {
	t.Helper()
	var b bytes.Buffer
	e := NewEncoder(&b)
	for _, f := range frames {
		if err := e.Write(f.kind, []byte(f.data)); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

func TestReadStreamBoundsAndCopies(t *testing.T) {
	raw := streamBytes(t, streamFrame{Stdout, "out"}, streamFrame{Stderr, "err"}, streamFrame{Events, "event"}, streamFrame{Outcome, goodOutcome})
	var kinds []Kind
	var logs bytes.Buffer
	got, err := ReadStream(context.Background(), bytes.NewReader(raw), 6, func(k Kind, b []byte) error {
		kinds = append(kinds, k)
		_, err := logs.Write(b)
		return err
	})
	if err != nil || got == nil {
		t.Fatal(err)
	}
	code, infra := got.ClaimedExit()
	if code != 0 || infra || got.LogBytes() != 6 || logs.String() != "outerr" || len(kinds) != 2 || kinds[0] != Stdout || kinds[1] != Stderr {
		t.Fatal("stream identities or claim changed")
	}
	copy := got.EventBytes()
	copy[0] = 'x'
	if string(got.EventBytes()) != "event" {
		t.Fatal("mutable retained events")
	}
}

func TestReadStreamRefusesMalformedClaimsAndOrder(t *testing.T) {
	cases := map[string][]streamFrame{
		"empty": {}, "missing outcome": {{Stdout, "log"}},
		"duplicate outcome":   {{Outcome, goodOutcome}, {Outcome, goodOutcome}},
		"log after outcome":   {{Outcome, goodOutcome}, {Stdout, "log"}},
		"event after outcome": {{Outcome, goodOutcome}, {Events, "event"}},
		"log after event":     {{Events, "event"}, {Stderr, "log"}, {Outcome, goodOutcome}},
		"shared log limit":    {{Stdout, "123"}, {Stderr, "456"}, {Outcome, goodOutcome}},
	}
	for name, claim := range map[string]string{
		"missing field": `{"exitCode":0}`, "unknown": `{"exitCode":0,"infrastructureFailure":false,"extra":1}`,
		"duplicate":  `{"exitCode":0,"exitCode":0,"infrastructureFailure":false}`,
		"whitespace": " " + goodOutcome, "trailing": goodOutcome + "{}", "null": "null",
		"fraction":               `{"exitCode":0.5,"infrastructureFailure":false}`,
		"negative":               `{"exitCode":-1,"infrastructureFailure":false}`,
		"overflow":               `{"exitCode":256,"infrastructureFailure":false}`,
		"infra success":          `{"exitCode":0,"infrastructureFailure":true}`,
		"reserved without infra": `{"exitCode":125,"infrastructureFailure":false}`,
	} {
		cases[name] = []streamFrame{{Outcome, claim}}
	}
	for name, frames := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ReadStream(context.Background(), bytes.NewReader(streamBytes(t, frames...)), 5, func(Kind, []byte) error { return nil })
			if got != nil || !errors.Is(err, ErrStream) {
				t.Fatal("invalid stream accepted", err)
			}
		})
	}
}

func TestReadStreamAggregateEventAndFrameLimits(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		var b bytes.Buffer
		e := NewEncoder(&b)
		for i := 0; i < MaximumEventBytes/MaximumChunk; i++ {
			if err := e.Write(Events, make([]byte, MaximumChunk)); err != nil {
				t.Fatal(err)
			}
		}
		if overflow {
			_ = e.Write(Events, []byte{1})
		}
		_ = e.Write(Outcome, []byte(goodOutcome))
		got, err := ReadStream(context.Background(), &b, 1, func(Kind, []byte) error { return nil })
		if overflow {
			if got != nil || !errors.Is(err, ErrStream) {
				t.Fatal("event overflow accepted")
			}
		} else if err != nil || len(got.EventBytes()) != MaximumEventBytes {
			t.Fatal("exact event bound refused", err)
		}
	}
	for _, overflow := range []bool{false, true} {
		var b bytes.Buffer
		e := NewEncoder(&b)
		count := MaximumFrames - 1
		if overflow {
			count++
		}
		for i := 0; i < count; i++ {
			_ = e.Write(Stdout, []byte{1})
		}
		_ = e.Write(Outcome, []byte(goodOutcome))
		got, err := ReadStream(context.Background(), &b, MaximumLogBytes, func(Kind, []byte) error { return nil })
		if overflow {
			if got != nil || !errors.Is(err, ErrStream) {
				t.Fatal("frame overflow accepted")
			}
		} else if err != nil || got.LogBytes() != int64(count) {
			t.Fatal("exact frame bound refused", err)
		}
	}
}

func TestReadStreamCancellationAndSinkFailure(t *testing.T) {
	raw := streamBytes(t, streamFrame{Stdout, "log"}, streamFrame{Outcome, goodOutcome})
	sentinel := errors.New("sink failed")
	got, err := ReadStream(context.Background(), bytes.NewReader(raw), 3, func(Kind, []byte) error { return sentinel })
	if got != nil || !errors.Is(err, sentinel) || !errors.Is(err, ErrStream) {
		t.Fatal("sink failure ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	got, err = ReadStream(ctx, bytes.NewReader(raw), 3, func(Kind, []byte) error { cancel(); return nil })
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	for _, raw := range [][]byte{raw[:len(raw)-1], append(raw, 1), []byte("invalid")} {
		got, err = ReadStream(context.Background(), bytes.NewReader(raw), 3, func(Kind, []byte) error { return nil })
		if got != nil || !errors.Is(err, ErrStream) {
			t.Fatal("truncation/trailing bytes accepted")
		}
	}
	got, err = ReadStream(context.Background(), io.MultiReader(bytes.NewReader(streamBytes(t, streamFrame{Outcome, `{"exitCode":125,"infrastructureFailure":true}`}))), 1, func(Kind, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	code, infra := got.ClaimedExit()
	if code != 125 || !infra {
		t.Fatal("infrastructure claim changed")
	}
}
