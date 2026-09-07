package evidence

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestStructuredScalarAndSyntaxSecretsFailClosed(t *testing.T) {
	for _, fixture := range []struct{ secret, payload string }{
		{"1234567", `{"n":1234567}`},
		{"true", `{"flag":true}`},
		{"null", `{"n":null}`},
		{`","next":"`, `{"first":"value","next":"value"}`},
	} {
		for _, direct := range []bool{false, true} {
			input := []byte("EVENT:" + fixture.payload + "\n")
			for split := 0; split <= len(input); split++ {
				c := newTestCollector(t, Config{Secrets: []string{fixture.secret}, StructuredLinePrefix: "EVENT:", StructuredLineKind: "probe"})
				var live bytes.Buffer
				c.SetLiveSink(func(e LiveEntry) { live.Write(e.Data) })
				if direct {
					if err := c.RecordEvent(context.Background(), EventInput{Kind: "probe", Payload: []byte(fixture.payload)}); err != nil {
						t.Fatal(err)
					}
				} else {
					writeChunks(t, c, StreamStdout, input[:split], input[split:])
				}
				b := snapshot(t, c)
				if len(b.Events) != 0 || b.StructuredEventError != "structured event cannot be safely sanitized" {
					t.Fatal("unsafe scalar or syntax accepted")
				}
				// len(Events)==0 above proves no event payload is retained; do
				// not mistake JSON's generated nil token for customer output.
				for _, value := range []string{b.Stdout, b.Stderr, live.String(), decompress(t, b.CompleteLog)} {
					if strings.Contains(value, fixture.secret) {
						t.Fatal("structured leak")
					}
				}
			}
		}
	}
}

func TestStructuredCrossBoundaryFullStreamMatching(t *testing.T) {
	for _, fixture := range []struct{ secret, input, want string }{
		{"AB\nEVENT:", "xxAB\nEVENT:{}\n", "xx[REDACTED]"},
		{"AB\nEVENT:{\"n\":\"secret", "xxAB\nEVENT:{\"n\":\"secret\"}\n", "xx[REDACTED]"},
		{"}\nAB", "EVENT:{}\nABzz\n", "[REDACTED]zz\n"},
	} {
		for split := 0; split <= len(fixture.input); split++ {
			c := newTestCollector(t, Config{Secrets: []string{fixture.secret}, StructuredLinePrefix: "EVENT:", StructuredLineKind: "probe"})
			var live bytes.Buffer
			c.SetLiveSink(func(e LiveEntry) { live.Write(e.Data) })
			writeChunks(t, c, StreamStdout, []byte(fixture.input[:split]), []byte(fixture.input[split:]))
			b := snapshot(t, c)
			if b.Stdout != fixture.want || live.String() != fixture.want || len(b.Events) != 0 || b.StructuredEventError != "structured event cannot be safely sanitized" {
				t.Fatalf("boundary output %q expected %q", b.Stdout, fixture.want)
			}
			archive := decompress(t, b.CompleteLog)
			if strings.Contains(archive, "AB") || strings.Contains(archive, "secret") || strings.Contains(archive, "EVENT:") {
				t.Fatal("boundary archive leak")
			}
		}
	}
}
