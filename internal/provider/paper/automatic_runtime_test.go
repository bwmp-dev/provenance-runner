package paper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
)

func automaticFixture(t *testing.T, origin string) (*RuntimeSource, SignedRuntime, resolvedCatalog) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	source, err := NewRuntimeSource(origin, hex.EncodeToString(key.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	c := operatorFixture()
	c.EnvironmentID = "paper-runtime-" + runtimeID(c.Paper.GameVersion, c.Paper.Build, c.Paper.Artifact.SHA256, c.Java.Distribution, c.Java.Version)
	for _, p := range []*ArtifactPin{&c.Paper.Artifact, &c.Java.Artifact, &c.Probe, &c.PreparedRuntime.Artifact} {
		p.URI = origin + "/v1/paper-runtime-assets/" + p.SHA256 + "/" + p.Filename
	}
	raw, _ := json.Marshal(struct {
		RuntimeID string  `json:"runtimeId"`
		Catalog   Catalog `json:"catalog"`
	}{runtimeID(c.Paper.GameVersion, c.Paper.Build, c.Paper.Artifact.SHA256, c.Java.Distribution, c.Java.Version), c})
	m := SignedRuntime{raw, ed25519.Sign(key, append([]byte(runtimeDomain), raw...))}
	resolved, err := source.verify(m)
	if err != nil {
		t.Fatal(err)
	}
	return source, m, resolved
}
func TestAutomaticRuntimeSignatureAndAuthority(t *testing.T) {
	source, m, c := automaticFixture(t, "https://api.example")
	if c.EnvironmentID == "" {
		t.Fatal("missing runtime identity")
	}
	broken := m
	broken.Payload = bytes.Clone(m.Payload)
	broken.Payload[len(broken.Payload)-2] ^= 1
	if _, err := source.verify(broken); err == nil {
		t.Fatal("tampering accepted")
	}
	other := *source
	other.PublicKey = make(ed25519.PublicKey, 32)
	if _, err := other.verify(m); err == nil {
		t.Fatal("wrong signing authority accepted")
	}
	other = *source
	other.Origin = "https://other.example"
	if _, err := other.verify(m); err == nil {
		t.Fatal("wrong artifact origin accepted")
	}
}
func TestAutomaticRuntimeFetchRejectsRedirectAndIdentitySwap(t *testing.T) {
	var m SignedRuntime
	var redirect bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("credential leaked")
		}
		if redirect {
			http.Redirect(w, r, "https://evil.example", 302)
			return
		}
		json.NewEncoder(w).Encode(m)
	}))
	defer server.Close()
	source, manifest, c := automaticFixture(t, server.URL)
	m = manifest
	source.Client = server.Client()
	e := exactRemoteEnvironment(t, c)
	if _, _, err := source.fetch(e); err != nil {
		t.Fatal(err)
	}
	e.ServerBuild++
	if _, _, err := source.fetch(e); err == nil {
		t.Fatal("different requested build accepted")
	}
	redirect = true
	e.ServerBuild--
	if _, _, err := source.fetch(e); err == nil {
		t.Fatal("redirect followed")
	}
}
func TestAutomaticRuntimeVerificationConcurrent(t *testing.T) {
	source, m, _ := automaticFixture(t, "https://api.example")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := source.verify(m); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestAutomaticRuntimeConsumesPublicProducerVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/automatic-runtime-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RuntimeID string        `json:"runtimeId"`
		PublicKey string        `json:"publicKey"`
		Origin    string        `json:"origin"`
		Manifest  SignedRuntime `json:"manifest"`
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	source, err := NewRuntimeSource(vector.Origin, vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := source.verify(vector.Manifest)
	if err != nil || c.EnvironmentID != "paper-runtime-"+vector.RuntimeID {
		t.Fatalf("public producer vector refused: %v", err)
	}
}

type runtimeTransport func(*http.Request) (*http.Response, error)

func (f runtimeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAutomaticJobRetainsManifestWithoutMutatingProviderCatalog(t *testing.T) {
	p, server, payloads := validationTestProvider(t)
	defer server.Close()
	source, m, c := automaticFixture(t, "https://api.example")
	raw, _ := json.Marshal(m)
	source.Client = &http.Client{Transport: runtimeTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw)), Header: http.Header{}}, nil
	})}
	p.config.RuntimeSource = source
	spec := validRemoteSpecification(t, server.URL, payloads)
	spec.Environment = exactRemoteEnvironment(t, c)
	job, err := p.AdaptJob(spec)
	if err != nil {
		t.Fatal(err)
	}
	var config configuration
	if json.Unmarshal(job.Environment, &config) != nil || config.RuntimeManifest == nil {
		t.Fatal("signed recovery manifest missing")
	}
	if _, exists := p.catalogs[c.EnvironmentID]; exists {
		t.Fatal("job changed shared provider catalog")
	}
	env, err := p.Resolve(context.Background(), execution.Request{JobID: job.ID, Environment: job.Environment})
	if err != nil {
		t.Fatal(err)
	}
	if env == nil {
		t.Fatal("automatic environment missing")
	}
	// Durable job replay uses retained signed bytes, without a fresh HTTP lookup.
	source.Client = nil
	if _, err = p.Resolve(context.Background(), execution.Request{JobID: job.ID, Environment: job.Environment}); err != nil {
		t.Fatal(err)
	}
	config.RuntimeManifest.Signature[0] ^= 1
	job.Environment, _ = json.Marshal(config)
	if _, err = p.Resolve(context.Background(), execution.Request{JobID: job.ID, Environment: job.Environment}); err == nil {
		t.Fatal("tampered retained manifest accepted")
	}
}
