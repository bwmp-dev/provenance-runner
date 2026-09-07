package terminalevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestReleasedAssetIdentityAndCanonicalVector(t *testing.T) {
	for path, want := range map[string]string{
		"schema/config.json":            "11015605ee709d3ea032c064065b411227d500b0c94cbdf640627189d3016778",
		"testdata/schema.json":          "838d75a63cfbecc0697c4fad38c484a8f4790c802f9f1d919a764edd1991657e",
		"testdata/reference.mjs":        "27da7c97fcb8aeab356a6edf101bdceceefb2f0170423cc21f1c2e0c09168326",
		"testdata/fixtures.json":        "db0555744db814e135e0374546fbf49211c40ae657ba357fa378dc3151a082aa",
		"testdata/vectors.json":         "186a4002b72bdae74129ef2248e030f7c95da72a935b2825790bb3d915e05923",
		"testdata/invalid-vectors.json": "1453a5aa67a5fc9387afff9d2c0c05c142ffd9cb0f1bbbd004cdff4b29a9b823",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		if hex.EncodeToString(hash[:]) != want {
			t.Fatalf("released identity changed: %s", path)
		}
	}
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct{ Canonical, SHA256 string }
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	value, err := parseJSON([]byte(vector.Canonical))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := canonicalJSON(value)
	if err != nil || !bytes.Equal(encoded, []byte(vector.Canonical)) {
		t.Fatal("released canonical vector changed")
	}
	hash := sha256.Sum256(encoded)
	if hex.EncodeToString(hash[:]) != vector.SHA256 {
		t.Fatal("released preimage digest changed")
	}
}

func TestCanonicalUnicodeNumbersAndBoundedJSON(t *testing.T) {
	input := []byte("{\"\ue000\":1,\"😀\":2,\"s\":\"<>&\\n\"}")
	value, err := parseJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{\"s\":\"<>&\\n\",\"😀\":2,\"\ue000\":1}" {
		t.Fatalf("UTF16/ECMAScript mismatch: %s", got)
	}
	for _, raw := range [][]byte{bytes.Repeat([]byte(" "), MaxEnvelopeBytes+1), []byte(`{"x":1,"x":2}`), []byte(`"\udfff"`), []byte(`[]false`)} {
		if _, err := parseJSON(raw); err == nil {
			t.Fatal("strict JSON accepted invalid input")
		}
	}
}
