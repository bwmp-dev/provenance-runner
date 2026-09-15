package paper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
)

func TestMeasuredDownloadOwnershipAndCacheVerification(t *testing.T) {
	cache, err := artifact.NewCache(t.TempDir(), artifact.CacheOptions{MaximumEntryBytes: 1024, MaximumTotalBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	// Byte/descriptor ownership test only; synthetic identities do not stand in
	// for signed runtime admission or kernel execution acceptance.
	payloads := []string{"first", "second"}
	var identities []MeasuredInputIdentity
	var downloads []measuredDownload
	for _, payload := range payloads {
		identities = append(identities, MeasuredInputIdentity{SizeBytes: uint64(len(payload)), SHA256: sha256.Sum256([]byte(payload))})
		downloads = append(downloads, measuredDownload{cache, artifact.SourceFunc(func(_ context.Context, out io.Writer) error {
			_, err := io.WriteString(out, payload)
			return err
		})})
	}
	raw := []byte("synthetic request")
	owned, err := acquireMeasuredDownloads(context.Background(), raw, identities, downloads)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	raw[0] ^= 1
	copy := owned.Request()
	copy[0] ^= 1
	if string(owned.Request()) != "synthetic request" {
		t.Fatal("mutable request escaped")
	}
	files := owned.Files()
	for i, file := range files {
		if _, err := file.Write([]byte("x")); err == nil {
			t.Fatal("writable handoff")
		}
		got, err := io.ReadAll(file)
		if err != nil || string(got) != payloads[i] {
			t.Fatal("wrong input bytes", err)
		}
	}
	if owned.Close() != nil || owned.Close() != nil || len(owned.Files()) != 0 || len(owned.Request()) != 0 {
		t.Fatal("close ownership")
	}
	for _, file := range files {
		if _, err := file.Stat(); err == nil {
			t.Fatal("descriptor leaked")
		}
	}
	identities[1].SHA256 = sha256.Sum256([]byte("wrong"))
	if value, err := acquireMeasuredDownloads(context.Background(), raw, identities, downloads); value != nil || err == nil {
		t.Fatal("bad downloaded hash accepted")
	}
}

func TestMeasuredDownloadAdmissionRejectsBeforeArtifactFetch(t *testing.T) {
	source, manifest, job := measuredPlanFixture(t)
	manifest.Signature[0] ^= 1
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	source.Client = &http.Client{Transport: runtimeTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Fatal("manifest credential leakage")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}
	policy, err := newHTTPSAllowlist([]string{"download.example"})
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{config: Config{RuntimeSource: source, MaximumPreparationBytes: 64 << 30}, inputPolicy: policy}
	if value, err := provider.PrepareMeasuredInputs(context.Background(), job); value != nil || err == nil || requests != 1 {
		t.Fatal("invalid signed catalog admitted", err, requests)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if value, err := provider.PrepareMeasuredInputs(ctx, job); value != nil || err == nil || requests != 1 {
		t.Fatal("cancelled admission fetched metadata")
	}
}

func TestRuntimeManifestFetchHonorsCallerCancellation(t *testing.T) {
	source, _, job := measuredPlanFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source.Client = &http.Client{Transport: runtimeTransport(func(request *http.Request) (*http.Response, error) {
		cancel()
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	if _, _, err := source.fetchContext(ctx, job.Environment); err == nil {
		t.Fatal("cancelled fetch succeeded")
	}
}
