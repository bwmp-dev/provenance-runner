package paper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
)

// This fixture only downloads and verifies bytes; it never extracts or executes
// a JAR. The published probe is supplied by the hash-pinned disposable image.
func TestMeasuredInputDownloadFixture(t *testing.T) {
	if os.Getenv("PROVENANCE_DISPOSABLE_DOWNLOAD_FIXTURE") != "1" {
		t.Skip("explicit disposable download fixture required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container required")
	}
	probe, err := os.ReadFile("/opt/provenance-fixture/paper-probe.jar")
	digest := sha256.Sum256(probe)
	if err != nil || int64(len(probe)) != AlphaProbeSizeBytes || hex.EncodeToString(digest[:]) != AlphaProbeSHA256 {
		t.Fatal("published probe fixture identity")
	}
	const origin = "https://example.com"
	source, _, catalog := automaticFixture(t, origin)
	_, _, job := measuredPlanFixture(t)
	payloads := map[string][]byte{"/target": []byte("target"), "/dependency": []byte("dependency")}
	pin := func(name string, raw []byte) ArtifactPin {
		digest := artifact.SHA256(raw).String()
		path := "/v1/paper-runtime-assets/" + digest + "/" + name
		payloads[path] = raw
		return ArtifactPin{URI: origin + path, Filename: name, SHA256: digest, SizeBytes: int64(len(raw))}
	}
	catalog.Java.Artifact = pin("java.tar.gz", []byte("synthetic java archive"))
	catalog.Java.MaximumExpandedBytes = 1024
	catalog.Paper.Artifact = pin("paper.jar", []byte("synthetic paper"))
	catalog.PreparedRuntime.Artifact = pin("runtime.tar.gz", []byte("synthetic prepared archive"))
	catalog.PreparedRuntime.MaximumExpandedBytes = 1024
	catalog.Probe = pin(catalog.Probe.Filename, probe)
	id := runtimeID(catalog.Paper.GameVersion, catalog.Paper.Build, catalog.Paper.Artifact.SHA256, catalog.Java.Distribution, catalog.Java.Version)
	catalog.EnvironmentID = "paper-runtime-" + id
	manifestBytes, err := json.Marshal(struct {
		RuntimeID string  `json:"runtimeId"`
		Catalog   Catalog `json:"catalog"`
	}{id, catalog.Catalog})
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	manifest := SignedRuntime{Payload: manifestBytes, Signature: ed25519.Sign(key, append([]byte(runtimeDomain), manifestBytes...))}
	resolved, err := source.verify(manifest)
	if err != nil {
		t.Fatal(err)
	}
	job.Environment = exactRemoteEnvironment(t, resolved)
	job.Artifact.Uri = origin + "/target"
	job.Dependencies[0].Object.Uri = origin + "/dependency"
	var requests atomic.Int32
	var corrupt atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Error("credential attached to fixture download")
		}
		if request.URL.Path == "/v1/paper-runtimes/"+id {
			_ = json.NewEncoder(out).Encode(manifest)
			return
		}
		if corrupt.Load() && request.URL.Path == "/target" {
			_, _ = io.WriteString(out, "other")
			return
		}
		raw, ok := payloads[request.URL.Path]
		if !ok {
			http.NotFound(out, request)
			return
		}
		_, _ = out.Write(raw)
	}))
	defer server.Close()
	localDialer := dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	client := server.Client()
	client.Transport.(*http.Transport).DialContext = localDialer.DialContext
	source.Client = client
	cacheRoot := t.TempDir()
	cache, err := artifact.NewCache(cacheRoot, artifact.CacheOptions{MaximumEntryBytes: 1 << 20, MaximumTotalBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := newHTTPSAllowlist([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{config: Config{RuntimeSource: source, HTTPClient: client, ArtifactCache: cache, JavaCache: cache, PaperCache: cache, ProbeCache: cache, RuntimeCache: cache, MaximumArtifactBytes: 1 << 20, MaximumDependencyBytes: 1 << 20, MaximumPreparationBytes: 8 << 20}, inputPolicy: policy, sourceResolver: staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}, sourceDialer: localDialer}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for iteration := 0; iteration < 2; iteration++ {
		preparationStarted := time.Now()
		owned, err := provider.PrepareMeasuredInputs(ctx, job)
		if err != nil {
			t.Fatal("full worker preparation", err)
		}
		if !owned.PreparationDeadline().After(preparationStarted) || owned.PreparationDeadline().After(preparationStarted.Add(job.EffectivePolicy.PreparationTimeout.AsDuration()+time.Second)) {
			t.Fatal("preparation deadline was not retained")
		}
		request := owned.Request()
		projected, _, decodeErr := DecodeMeasuredRequest(request)
		if decodeErr != nil || projected.Artifact.Uri != "" || projected.Dependencies[0].Object.Uri != "" {
			t.Fatal("target transfer capability leaked to root request")
		}
		plan, err := source.PrepareMeasuredRequest(request, 8<<20)
		if err != nil || len(owned.Files()) != len(plan.Inputs()) {
			t.Fatal("root request cannot independently derive inputs", err)
		}
		for i, file := range owned.Files() {
			raw, err := io.ReadAll(file)
			identity := plan.Inputs()[i]
			if err != nil || uint64(len(raw)) != identity.SizeBytes || sha256.Sum256(raw) != identity.SHA256 {
				t.Fatal("handoff content identity", err)
			}
			if _, err := file.Write([]byte("x")); err == nil {
				t.Fatal("writable handoff")
			}
		}
		if owned.Close() != nil {
			t.Fatal("handoff cleanup")
		}
		// First pass fetches a manifest plus six artifacts; second pass only
		// fetches the current signed manifest and re-verifies cached inputs.
		if requests.Load() != int32(7+iteration) {
			t.Fatal("unexpected download or missed cache reuse", requests.Load())
		}
	}
	// Force a target cache miss with same-size corrupt bytes after the four
	// valid runtime descriptors were acquired. No partial handoff may escape.
	provider.config.ArtifactCache, err = artifact.NewCache(t.TempDir(), artifact.CacheOptions{MaximumEntryBytes: 1 << 20, MaximumTotalBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	corrupt.Store(true)
	if owned, err := provider.PrepareMeasuredInputs(ctx, job); owned != nil || err == nil || requests.Load() != 10 {
		t.Fatal("corrupt target admitted or unexpected fetches", err, requests.Load())
	}
	descriptors, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range descriptors {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", descriptor.Name()))
		if err == nil && strings.HasPrefix(target, cacheRoot+string(os.PathSeparator)) {
			t.Fatal("partial preparation retained a runtime descriptor")
		}
	}
}
