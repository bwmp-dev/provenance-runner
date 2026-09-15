package evidence

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/guestoutput"
)

func guestFixture(t *testing.T, stdout []string, events string, outcome bool) []byte {
	t.Helper()
	var b bytes.Buffer
	e := guestoutput.NewEncoder(&b)
	for _, s := range stdout {
		if err := e.Write(guestoutput.Stdout, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	for len(events) > 0 {
		n := len(events)
		if n > guestoutput.MaximumChunk {
			n = guestoutput.MaximumChunk
		}
		if err := e.Write(guestoutput.Events, []byte(events[:n])); err != nil {
			t.Fatal(err)
		}
		events = events[n:]
	}
	if outcome {
		_ = e.Write(guestoutput.Outcome, []byte(`{"exitCode":0,"infrastructureFailure":false}`))
	}
	return b.Bytes()
}

func TestGuestCollectionRedactsAcrossFramesAndSeparatesEvents(t *testing.T) {
	const secret = "synthetic-framed-secret"
	c, err := NewCollector(Config{Secrets: []string{secret}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var live bytes.Buffer
	c.SetLiveSink(func(e LiveEntry) { live.Write(e.Data) })
	raw := guestFixture(t, []string{"synthetic-framed-", "secret\n{\"type\":\"SERVER_READY\"}\n"}, "{\"message\":\""+secret+"\"}\n", true)
	transcript, err := c.ConsumeGuest(context.Background(), bytes.NewReader(raw), 1024)
	if err != nil || transcript == nil {
		t.Fatal(err)
	}
	b, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer b.CompleteLog.Archive.Close()
	if len(b.Events) != 1 || b.Events[0].Kind != "probe" || strings.Contains(string(b.Events[0].Payload), secret) || !strings.Contains(string(b.Events[0].Payload), RedactionMarker) {
		t.Fatal("event redaction/channel changed")
	}
	if strings.Contains(b.Stdout, secret) || strings.Contains(live.String(), secret) || !strings.Contains(b.Stdout, RedactionMarker) || !strings.Contains(b.Stdout, "SERVER_READY") {
		t.Fatal("raw log redaction/channel changed")
	}
	z, err := gzip.NewReader(b.CompleteLog.Archive)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	archive, err := io.ReadAll(z)
	if err != nil || bytes.Contains(archive, []byte(secret)) || !bytes.Contains(archive, []byte(RedactionMarker)) || b.CompleteLog.State != CompleteLogStateComplete {
		t.Fatal("complete archive leaked or incomplete")
	}
	if got, err := c.ConsumeGuest(context.Background(), bytes.NewReader(raw), 1024); got != nil || err == nil {
		t.Fatal("reused collector")
	}
}

func TestGuestCollectionMalformedEventsAndPartialStreamRefuse(t *testing.T) {
	for name, events := range map[string]string{"partial": "{}", "blank": "\n", "invalid": "no-json\n", "many": strings.Repeat("{}\n", 3), "large": "{\"v\":\"" + strings.Repeat("x", 80) + "\"}\n"} {
		t.Run(name, func(t *testing.T) {
			c, err := NewCollector(Config{MaxEvents: 2, MaxEventBytes: 64})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			got, err := c.ConsumeGuest(context.Background(), bytes.NewReader(guestFixture(t, []string{"diagnostic\n"}, events, true)), 1024)
			if got != nil || !errors.Is(err, guestoutput.ErrStream) {
				t.Fatal("malformed event stream accepted", err)
			}
			if next, err := c.ConsumeGuest(context.Background(), bytes.NewReader(guestFixture(t, nil, "", true)), 1024); next != nil || err == nil {
				t.Fatal("failed stream resumed")
			}
		})
	}
	c, err := NewCollector(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got, err := c.ConsumeGuest(context.Background(), bytes.NewReader(guestFixture(t, []string{"diagnostic\n"}, "", false)), 1024); got != nil || err == nil {
		t.Fatal("missing outcome accepted")
	}
	b, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer b.CompleteLog.Archive.Close()
	if !strings.Contains(b.Stdout, "diagnostic") {
		t.Fatal("failure diagnostics discarded")
	}
	if b.StructuredEventError == "" {
		t.Fatal("failed stream not marked in collected evidence")
	}
}

func TestGuestCollectionRefusesMixedRawEventRouting(t *testing.T) {
	c, err := NewCollector(Config{StructuredLinePrefix: "EVENT ", StructuredLineKind: "probe"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got, err := c.ConsumeGuest(context.Background(), bytes.NewReader(guestFixture(t, nil, "", true)), 1024); got != nil || err == nil {
		t.Fatal("raw event routing enabled")
	}
}
