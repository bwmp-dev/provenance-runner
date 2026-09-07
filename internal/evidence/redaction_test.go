package evidence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func testVariants(secret string) []string {
	return []string{secret, base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawStdEncoding.EncodeToString([]byte(secret)), base64.URLEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret)), hex.EncodeToString([]byte(secret)), strings.ToUpper(hex.EncodeToString([]byte(secret)))}
}

func TestTransformedSecretsEverySplitEveryOutput(t *testing.T) {
	secret := "ÿ?token-π"
	for variant, encoded := range testVariants(secret) {
		for split := 0; split <= len(encoded); split++ {
			t.Run(fmt.Sprintf("%d/%d", variant, split), func(t *testing.T) {
				c := newTestCollector(t, Config{Secrets: []string{secret}})
				var live bytes.Buffer
				c.SetLiveSink(func(entry LiveEntry) {
					if !entry.Redacted {
						t.Error("missing redacted flag")
					}
					live.Write(entry.Data)
				})
				for _, stream := range []Stream{StreamStdout, StreamStderr} {
					writeChunks(t, c, stream, []byte("before "+encoded[:split]), []byte(encoded[split:]+" after\n"))
				}
				b := snapshot(t, c)
				want := "before " + RedactionMarker + " after\n"
				if b.Stdout != want || b.Stderr != want || live.String() != want+want {
					t.Fatal("incorrect sanitized output")
				}
				archive := decompress(t, b.CompleteLog)
				if strings.Contains(archive, encoded) || strings.Contains(archive, secret) {
					t.Fatal("archive leak")
				}
			})
		}
	}
}

func runRedactor(t testing.TB, secrets []string, input []byte, chunk int) string {
	t.Helper()
	patterns, err := compileSecrets(secrets)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	r := newSecretRedactor(patterns, func(b []byte, _ bool) { out.Write(b) })
	for len(input) > 0 {
		n := min(chunk, len(input))
		r.write(input[:n])
		input = input[n:]
	}
	r.finish()
	return out.String()
}

func TestRedactionOverlapUnionAndMarkerNotRecursive(t *testing.T) {
	for _, chunk := range []int{1, 2, 3, 128} {
		if got := runRedactor(t, []string{"abc", "bcd", "cde", "[REDACTED]"}, []byte("abcde!"), chunk); got != RedactionMarker+"!" {
			t.Fatal(got)
		}
		if got := runRedactor(t, []string{"aba"}, []byte("abababa"), chunk); got != RedactionMarker {
			t.Fatal(got)
		}
	}
}

func TestNormalizedSecretAndHostileSurroundings(t *testing.T) {
	c := newTestCollector(t, Config{Secrets: []string{"a\x1b[31mbπ"}, MaxLineBytes: 16})
	input := append([]byte{0xff, 0x00}, []byte("a\x1b[32mbπ"+strings.Repeat("z", 100)+"\n")...)
	for _, value := range input {
		writeChunks(t, c, StreamStdout, []byte{value})
	}
	b := snapshot(t, c)
	if !utf8.ValidString(b.Stdout) || !strings.Contains(b.Stdout, RedactionMarker) || strings.Contains(b.Stdout, "abπ") || !b.Usage.OutputTruncated {
		t.Fatal("normalization/truncation mismatch")
	}
}

func TestAllVariantsWithInterspersedANSI(t *testing.T) {
	secret := "ÿ?private"
	for _, variant := range testVariants(secret) {
		var hostile strings.Builder
		for _, value := range variant {
			hostile.WriteRune(value)
			hostile.WriteString("\x1b[31m")
		}
		c := newTestCollector(t, Config{Secrets: []string{secret}})
		for _, b := range []byte(hostile.String() + "\n") {
			writeChunks(t, c, StreamStdout, []byte{b})
		}
		if got := snapshot(t, c).Stdout; got != RedactionMarker+"\n" {
			t.Fatal("interspersed ANSI bypass")
		}
	}
}

func TestStructuredRedactionDecodedStringsAndUnsafeKeys(t *testing.T) {
	secret := "a\"b\\π"
	for _, line := range []bool{false, true} {
		for _, variant := range testVariants(secret) {
			c := newTestCollector(t, Config{Secrets: []string{secret}, StructuredLinePrefix: "EVENT:", StructuredLineKind: "probe"})
			payload, _ := json.Marshal(map[string]any{"value": variant, "nested": []any{variant, json.Number("9007199254740993")}})
			if line {
				writeChunks(t, c, StreamStdout, append(append([]byte("EVENT:"), payload...), '\n'))
			} else if err := c.RecordEvent(context.Background(), EventInput{Kind: "probe", Payload: payload}); err != nil {
				t.Fatal(err)
			}
			b := snapshot(t, c)
			if len(b.Events) != 1 || !json.Valid(b.Events[0].Payload) {
				t.Fatal("invalid or missing event")
			}
			var decoded map[string]json.RawMessage
			json.Unmarshal(b.Events[0].Payload, &decoded)
			var value string
			json.Unmarshal(decoded["value"], &value)
			if value != RedactionMarker || !bytes.Contains(decoded["nested"], []byte("9007199254740993")) {
				t.Fatal("string/number changed incorrectly")
			}
		}
	}
	for _, payload := range []string{`{"token":"one","[REDACTED]":"two"}`, `{"safe":"one","safe":"two"}`} {
		c := newTestCollector(t, Config{Secrets: []string{"token"}})
		c.RecordEvent(context.Background(), EventInput{Kind: "probe", Payload: []byte(payload)})
		b := snapshot(t, c)
		if len(b.Events) != 0 || b.StructuredEventError != "structured event cannot be safely sanitized" {
			t.Fatal("unsafe keys not rejected")
		}
	}
	c := newTestCollector(t, Config{Secrets: []string{"probe"}})
	c.RecordEvent(context.Background(), EventInput{Kind: "probe", Payload: []byte(`{}`)})
	if b := snapshot(t, c); len(b.Events) != 0 || b.StructuredEventError == "" {
		t.Fatal("secret kind leaked")
	}
}

func TestRedactionExpansionBoundsAndOwnership(t *testing.T) {
	secrets := make([]string, 64)
	for i := range secrets {
		secrets[i] = "ÿ?\x1b[31m" + fmt.Sprintf("%04d", i) + strings.Repeat("z", 1012)
	}
	c, err := (Config{Secrets: secrets}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if c.patterns.count > 512 || c.patterns.size > 768<<10 || c.patterns.maximum > 128<<10 || len(c.patterns.nodes) > 1+c.patterns.size {
		t.Fatal("expansion unbounded")
	}
	if c.patterns.count != 512 || c.patterns.size != 742848 {
		t.Fatal("maximum-count expansion changed")
	}
	secrets[0] = "mutated"
	if c.Secrets[0] == secrets[0] {
		t.Fatal("caller aliases config")
	}
	large := strings.Repeat("a", 64<<10)
	p, err := compileSecrets([]string{large})
	if err != nil || p.maximum != 128<<10 {
		t.Fatal("maximum formerly valid secret rejected")
	}
	r := newSecretRedactor(p, func([]byte, bool) {})
	r.write([]byte(strings.Repeat("a", 256<<10)))
	r.finish()
	if len(r.pending) != 128<<10 {
		t.Fatal("holdback changed")
	}
	for _, bad := range [][]string{{strings.Repeat("a", (64<<10)+1)}, make([]string, 65)} {
		if ValidateConfig(Config{Secrets: bad}) == nil {
			t.Fatal("invalid raw config accepted")
		}
	}
}

func TestTransformedTruncationAndStructuredLimits(t *testing.T) {
	secret := "sensitive-token"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	for start := 0; start < 20; start++ {
		c := newTestCollector(t, Config{Secrets: []string{secret}, MaxLineBytes: 16, MaxTotalBytes: 64})
		writeChunks(t, c, StreamStdout, []byte(strings.Repeat("x", start)+encoded+strings.Repeat("z", 100)+"\n"))
		b := snapshot(t, c)
		if strings.Contains(b.Stdout, encoded) || strings.Contains(decompress(t, b.CompleteLog), encoded) {
			t.Fatal("truncation leaked match")
		}
	}
	c := newTestCollector(t, Config{Secrets: []string{"x"}, MaxEventBytes: 8})
	c.RecordEvent(context.Background(), EventInput{Kind: "probe", Payload: []byte(`"x"`)})
	if b := snapshot(t, c); len(b.Events) != 0 || b.StructuredEventError == "" {
		t.Fatal("expanded event escaped limit")
	}
	c = newTestCollector(t, Config{Secrets: []string{"secret"}, StructuredLinePrefix: "EVENT:", StructuredLineKind: "probe"})
	writeChunks(t, c, StreamStdout, []byte("raw secret\nEVENT:{\"value\":\"secret\"}\nraw secret\n"))
	writeChunks(t, c, StreamStderr, []byte("EVENT:secret\n"))
	b := snapshot(t, c)
	if b.Stdout != "raw [REDACTED]\nraw [REDACTED]\n" || b.Stderr != "EVENT:[REDACTED]\n" || len(b.Events) != 1 {
		t.Fatal("routing order or sanitization incorrect")
	}
}

func FuzzRedactionChunkIndependent(f *testing.F) {
	f.Add("ababa", "xxabababaxx", uint8(1))
	f.Add("π?", "π?π?", uint8(3))
	f.Fuzz(func(t *testing.T, secret, input string, split uint8) {
		if secret == "" || !utf8.ValidString(secret) || strings.ContainsRune(secret, '\x1b') || len(secret) > 64 || len(input) > 4096 {
			t.Skip()
		}
		want := runRedactor(t, []string{secret}, []byte(input), max(1, len(input)))
		got := runRedactor(t, []string{secret}, []byte(input), int(split)+1)
		if got != want {
			t.Fatal("chunk-dependent match")
		}
		// Independent exhaustive occurrence oracle, including overlapping hits.
		mask := make([]bool, len(input))
		for _, pattern := range testVariants(secret) {
			for start := 0; start+len(pattern) <= len(input); start++ {
				if input[start:start+len(pattern)] == pattern {
					for i := start; i < start+len(pattern); i++ {
						mask[i] = true
					}
				}
			}
		}
		var oracle strings.Builder
		for i := range len(input) {
			if !mask[i] {
				oracle.WriteByte(input[i])
			} else if i == 0 || !mask[i-1] {
				oracle.WriteString(RedactionMarker)
			}
		}
		if got != oracle.String() {
			t.Fatal("match differs from exhaustive overlap oracle")
		}
	})
}
