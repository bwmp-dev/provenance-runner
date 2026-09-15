//go:build linux

package paper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Invoked only as the non-root child of the disposable root service fixture.
// Supplied JAR bytes are data; the fixed synthetic stand-in executes in gVisor.
func TestMeasuredWorkerRootFixture(t *testing.T) {
	endpoint := os.Getenv("PROVENANCE_DISPOSABLE_WORKER_ROOT_SOCKET")
	if endpoint == "" {
		t.Skip("explicit disposable root fixture required")
	}
	if os.Getuid() != 65532 || os.Getgid() != 65532 || os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" {
		t.Fatal("disposable non-root worker required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("container required")
	}
	read := func(fd uintptr, limit int64) []byte {
		file := os.NewFile(fd, "synthetic worker input")
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil || int64(len(raw)) > limit {
			t.Fatal("bounded fixture input")
		}
		return raw
	}
	job, manifest, err := DecodeMeasuredRequest(read(3, cc.MaximumStartBytes))
	if err != nil {
		t.Fatal(err)
	}
	update, err := np.DecodeAuthorityUpdate(read(4, 16<<10))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		RuntimeID string  `json:"runtimeId"`
		Catalog   Catalog `json:"catalog"`
	}
	if json.Unmarshal(manifest.Payload, &payload) != nil {
		t.Fatal("fixture manifest")
	}
	u, err := url.Parse(payload.Catalog.Java.Artifact.URI)
	if err != nil {
		t.Fatal(err)
	}
	origin := u.Scheme + "://" + u.Host
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{57}, 32))
	source, err := NewRuntimeSource(origin, hex.EncodeToString(key.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	assets := make(map[string][]byte)
	for index, pin := range []ArtifactPin{payload.Catalog.Java.Artifact, payload.Catalog.Paper.Artifact, payload.Catalog.Probe, payload.Catalog.PreparedRuntime.Artifact} {
		u, err := url.Parse(pin.URI)
		if err != nil {
			t.Fatal(err)
		}
		assets[u.Path] = read(uintptr(5+index), 64<<20)
	}
	assets["/target"] = read(9, 64<<20)
	_ = read(10, 64<<10) // Worker independently regenerates the exact probe plan.
	job.Artifact.Uri = origin + "/target"
	server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Error("unexpected download credential")
		}
		if request.URL.Path == "/v1/paper-runtimes/"+payload.RuntimeID {
			_ = json.NewEncoder(out).Encode(manifest)
			return
		}
		if raw, ok := assets[request.URL.Path]; ok {
			_, _ = out.Write(raw)
			return
		}
		http.NotFound(out, request)
	}))
	defer server.Close()
	dialer := dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	client := server.Client()
	client.Transport.(*http.Transport).DialContext = dialer.DialContext
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = "example.com"
	source.Client = client
	cache, err := artifact.NewCache(t.TempDir(), artifact.CacheOptions{MaximumEntryBytes: 64 << 20, MaximumTotalBytes: 128 << 20})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewMeasured(Config{RuntimeSource: source, HTTPClient: client, ArtifactCache: cache, JavaCache: cache, PaperCache: cache, ProbeCache: cache, RuntimeCache: cache, ArtifactHosts: []string{u.Hostname()}, MaximumArtifactBytes: 64 << 20, MaximumDependencyBytes: 64 << 20, MaximumPreparationBytes: 128 << 20,
		sourceResolver: staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}, sourceDialer: dialer})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if provider.CheckMeasuredService(ctx, endpoint) != nil {
		t.Fatal("startup root idle barrier refused")
	}
	guard, err := np.NewAuthorityRoute(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	update.Reconciliation.NetworkAuthorityV2.CheckedAt = timestamppb.New(now)
	update.Reconciliation.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(40 * time.Second))
	if guard.Reconcile(ctx, update.Reconciliation, update.Features, update.CredentialExpiry) != nil {
		t.Fatal("fixture authority refused")
	}
	starts := 0
	result := execution.SuperviseNetworkAuthority(ctx, job, guard, func(ctx context.Context) execution.Result {
		return provider.ExecuteMeasured(ctx, job, endpoint, func(context.Context, execution.ExecutionStart) error { starts++; return nil })
	})
	if result.CompleteLog != nil && result.CompleteLog.Archive != nil {
		defer result.CompleteLog.Archive.Close()
	}
	// The deliberately non-Protocol probe event MUST fail Paper validation,
	// despite a successful root process and authenticated runtime observation.
	if starts != 1 || result.Classification != execution.ClassificationWorkloadFailure || result.Cleanup == nil || !result.Cleanup.Succeeded || result.MeasuredNetwork == nil || result.Logs == nil || !strings.Contains(result.Logs.Stdout, "ROOT_SERVICE_OK") {
		t.Fatalf("worker composition: starts=%d classification=%s phase=%s failure=%v cleanup=%v", starts, result.Classification, result.Phase, result.Failure, result.Cleanup)
	}
	frozen, err := result.FreezeTerminalEvidence("fixture-runner")
	if err != nil || frozen == nil || terminalevidence.ValidateFrozenV2(frozen, job, "fixture-runner") != nil {
		t.Fatal("worker terminal evidence lost exact root observation", err)
	}
}
