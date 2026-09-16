//go:build linux

package paper

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

func TestMeasuredProviderHasNoLegacySandbox(t *testing.T) {
	source, _, _ := automaticFixture(t, "https://example.com")
	cache, err := artifact.NewCache(t.TempDir(), artifact.CacheOptions{MaximumEntryBytes: 1 << 20, MaximumTotalBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{RuntimeSource: source, ArtifactCache: cache, JavaCache: cache, PaperCache: cache, ProbeCache: cache, RuntimeCache: cache, ArtifactHosts: []string{"example.com"}}
	provider, err := NewMeasured(config)
	if err != nil || provider.config.Sandbox != nil || provider.config.Workspaces != nil {
		t.Fatal("separate provider construction", err)
	}
	if _, err := provider.Resolve(context.Background(), execution.Request{}); err == nil {
		t.Fatal("legacy resolution allowed")
	}
	if _, err := New(config); err == nil {
		t.Fatal("legacy constructor accepted missing sandbox")
	}
	config.RuntimeSource = nil
	if _, err := NewMeasured(config); err == nil {
		t.Fatal("unsigned runtime source allowed")
	}
	if result := provider.ExecuteMeasured(context.Background(), nil, "/run/missing.sock", nil); result.Failure == nil {
		t.Fatal("missing job admitted")
	}
	_, _, job := measuredPlanFixture(t)
	if result := provider.ExecuteMeasured(context.Background(), job, "/run/missing.sock", nil); result.Failure == nil || result.MeasuredNetwork != nil {
		t.Fatal("missing v2 authority admitted")
	}
}

func TestMeasuredWorkerCleanupRefusesUnknownRootRetirement(t *testing.T) {
	collector, err := evidence.NewCollector(evidence.Config{})
	if err != nil {
		t.Fatal(err)
	}
	session := &measuredWorkerSession{collector: collector, contacted: true, endpoint: filepath.Join(t.TempDir(), "missing.sock")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if session.Cleanup(ctx) == nil || session.retired {
		t.Fatal("unknown root cleanup declared successful")
	}
	if session.accepted != nil {
		t.Fatal("cleanup fabricated an execution result")
	}
}

func TestMeasuredWorkerRefusesNonRootPeer(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("non-root peer test requires non-root test process")
	}
	directory, err := os.MkdirTemp("/tmp", "measured-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(directory)
	endpoint := filepath.Join(directory, "control.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: endpoint, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	channel, err := dialMeasuredRoot(ctx, endpoint)
	if channel != nil || err == nil {
		t.Fatal("non-root service authenticated")
	}
}
