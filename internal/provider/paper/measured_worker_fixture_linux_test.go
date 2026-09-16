//go:build linux

package paper

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
	"sync"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type measuredSecretFixtureObserver struct {
	mu   sync.Mutex
	logs bytes.Buffer
}

func (o *measuredSecretFixtureObserver) ObserveLog(entry execution.LiveLogEntry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.logs.Write(entry.Data)
}
func (*measuredSecretFixtureObserver) ObserveUsage(execution.ResourceUsage) {}

// Invoked only as the non-root child of the disposable root service fixture.
// Supplied JAR bytes are data; the fixed synthetic stand-in executes in gVisor.
func TestMeasuredWorkerRootFixture(t *testing.T) {
	endpoint := os.Getenv("PROVENANCE_DISPOSABLE_WORKER_ROOT_SOCKET")
	realPaper := os.Getenv("PROVENANCE_DISPOSABLE_REAL_PAPER_FIXTURE") == "1"
	maximumArtifact, maximumPreparation, maximumCache := int64(64<<20), int64(128<<20), int64(128<<20)
	budget := 35 * time.Second
	if realPaper {
		maximumArtifact, maximumPreparation, maximumCache, budget = 256<<20, 512<<20, 768<<20, 280*time.Second
	}
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
		assets[u.Path] = read(uintptr(5+index), maximumArtifact)
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
	cache, err := artifact.NewCache(t.TempDir(), artifact.CacheOptions{MaximumEntryBytes: maximumArtifact, MaximumTotalBytes: maximumCache})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewMeasured(Config{RuntimeSource: source, HTTPClient: client, ArtifactCache: cache, JavaCache: cache, PaperCache: cache, ProbeCache: cache, RuntimeCache: cache, ArtifactHosts: []string{u.Hostname()}, MaximumArtifactBytes: maximumArtifact, MaximumDependencyBytes: maximumArtifact, MaximumPreparationBytes: maximumPreparation,
		sourceResolver: staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}, sourceDialer: dialer})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if provider.CheckMeasuredService(ctx, endpoint) != nil {
		t.Fatal("startup root idle barrier refused")
	}
	if os.Getenv("PROVENANCE_DISPOSABLE_GATEWAY_FIXTURE") == "1" {
		runMeasuredGatewayFixture(t, ctx, provider, endpoint, job)
		return
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
	renewCtx, stopRenew := context.WithCancel(ctx)
	renewDone := make(chan struct{})
	go func() {
		defer close(renewDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				update.Reconciliation.NetworkAuthorityV2.CheckedAt = timestamppb.New(now)
				update.Reconciliation.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(40 * time.Second))
				if guard.Reconcile(renewCtx, update.Reconciliation, update.Features, update.CredentialExpiry) != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { stopRenew(); <-renewDone }()
	starts := 0
	secretCalls := 0
	observer := &measuredSecretFixtureObserver{}
	encodedSecret := base64.StdEncoding.EncodeToString([]byte("synthetic-session-secret"))
	if len(job.TestSecrets) > 0 {
		ctx = execution.WithObserver(ctx, observer)
		ctx = execution.WithTestSecretSource(ctx, func(context.Context) (*ts.Files, time.Time, error) {
			secretCalls++
			if starts != 0 || secretCalls != 1 {
				t.Error("secret acquired after start acknowledgement or more than once")
			}
			files, err := ts.New([]ts.Input{{Name: "license", Value: []byte("synthetic-session-secret")}})
			return files, time.Now().Add(20 * time.Second), err
		})
	}
	result := execution.SuperviseNetworkAuthority(ctx, job, guard, func(ctx context.Context) execution.Result {
		defer func() { stopRenew(); <-renewDone }()
		return provider.ExecuteMeasured(ctx, job, endpoint, func(context.Context, execution.ExecutionStart) error { starts++; return nil })
	})
	if result.CompleteLog != nil && result.CompleteLog.Archive != nil {
		defer result.CompleteLog.Archive.Close()
	}
	// The deliberately non-Protocol probe event MUST fail Paper validation,
	// despite a successful root process and authenticated runtime observation.
	wantClassification, marker := execution.ClassificationWorkloadFailure, "ROOT_SERVICE_OK"
	if realPaper {
		wantClassification, marker = execution.ClassificationPassed, "Paper"
	}
	if starts != 1 || result.Classification != wantClassification || result.Cleanup == nil || !result.Cleanup.Succeeded || result.MeasuredNetwork == nil || result.Logs == nil || !strings.Contains(result.Logs.Stdout, marker) {
		// Both inputs are fixed disposable fixtures. Keep diagnostics bounded
		// for synthetic startup failures as well as real Paper failures.
		if result.Logs != nil {
			out, diagnostic := result.Logs.Stdout, result.Logs.Stderr
			if len(out) > 4096 {
				out = out[len(out)-4096:]
			}
			if len(diagnostic) > 4096 {
				diagnostic = diagnostic[len(diagnostic)-4096:]
			}
			t.Logf("bounded fixture diagnostics: stdout=%s stderr=%s", out, diagnostic)
		}
		t.Fatalf("worker composition: starts=%d classification=%s phase=%s failure=%v cleanup=%v", starts, result.Classification, result.Phase, result.Failure, result.Cleanup)
	}
	if len(job.TestSecrets) > 0 {
		if secretCalls != 1 || strings.Contains(result.Logs.Stdout+result.Logs.Stderr, "synthetic-session-secret") || strings.Contains(result.Logs.Stdout+result.Logs.Stderr, encodedSecret) || !strings.Contains(result.Logs.Stdout, evidence.RedactionMarker) || !strings.Contains(result.Logs.Stdout, "ROOT_SECRET_READ_ONLY_OK") {
			t.Fatal("late worker injection or redaction failed")
		}
		observer.mu.Lock()
		live := observer.logs.String()
		observer.mu.Unlock()
		if strings.Contains(live, "synthetic-session-secret") || strings.Contains(live, encodedSecret) || !strings.Contains(live, evidence.RedactionMarker) {
			t.Fatal("late live redaction failed")
		}
		if result.CompleteLog == nil || result.CompleteLog.Archive == nil || result.CompleteLog.State != "complete" {
			t.Fatal("secret complete archive missing")
		}
		archive, err := gzip.NewReader(io.NewSectionReader(result.CompleteLog.Archive, 0, result.CompleteLog.CompressedBytes))
		if err != nil {
			t.Fatal("secret archive framing")
		}
		complete, readErr := io.ReadAll(io.LimitReader(archive, (16<<20)+1))
		closeErr := archive.Close()
		if readErr != nil || closeErr != nil || len(complete) > 16<<20 || bytes.Contains(complete, []byte("synthetic-session-secret")) || bytes.Contains(complete, []byte(encodedSecret)) || !bytes.Contains(complete, []byte(evidence.RedactionMarker)) {
			t.Fatal("late archive redaction failed")
		}
	}
	frozen, err := result.FreezeTerminalEvidence("fixture-runner")
	if err != nil || frozen == nil || terminalevidence.ValidateFrozenV2(frozen, job, "fixture-runner") != nil {
		t.Fatal("worker terminal evidence lost exact root observation", err)
	}
}
