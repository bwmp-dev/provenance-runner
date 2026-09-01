//go:build linux

package gvisor

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

func TestRunscSmoke(t *testing.T) {
	if os.Getenv("PROVENANCE_RUNSC_SMOKE") != "1" {
		t.Skip("set PROVENANCE_RUNSC_SMOKE=1 to opt in to the real sandbox smoke test")
	}
	runscPath := os.Getenv("PROVENANCE_RUNSC_PATH")
	if runscPath == "" {
		runscPath = "runsc"
	}
	resolvedRunsc, err := exec.LookPath(runscPath)
	if err != nil {
		t.Fatalf("PROVENANCE_RUNSC_SMOKE=1 requires runsc (%v)", err)
	}
	rootFS := os.Getenv("PROVENANCE_RUNSC_ROOTFS")
	if rootFS == "" {
		t.Fatal("PROVENANCE_RUNSC_SMOKE=1 requires PROVENANCE_RUNSC_ROOTFS containing /bin/sh")
	}

	temporaryRoot := t.TempDir()
	inputsRoot := filepath.Join(temporaryRoot, "inputs")
	if err := os.MkdirAll(filepath.Join(inputsRoot, "smoke"), 0o700); err != nil {
		t.Fatal(err)
	}
	provider, err := New(Config{
		RunscPath:      resolvedRunsc,
		RootFS:         rootFS,
		RootFSIdentity: "smoke-rootfs",
		StateRoot:      filepath.Join(temporaryRoot, "state"),
		BundleRoot:     filepath.Join(temporaryRoot, "bundles"),
		InputsRoot:     inputsRoot,
		Platform:       "systrap",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := provider.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	config := configuration{
		Command:     "/bin/sh",
		Arguments:   []string{"-c", `test "$(id -u)" = 65532 && test "$TMPDIR" = /tmp && touch /workspace/ok && touch /tmp/ok && ! touch /provenance-root-write-test && test ! -S /run/docker.sock && echo gvisor-smoke-ok`},
		Network:     "none",
		MemoryBytes: 128 << 20,
		CPUMillis:   500,
		PIDs:        64,
		DiskBytes:   8 << 20,
	}
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := provider.Resolve(context.Background(), execution.Request{
		JobID:       "smoke",
		Environment: content,
		Limits:      execution.Limits{MaxOutputBytes: 64 << 10},
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	prepared, err := environment.Prepare(ctx)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cleanupCancel()
		if err := prepared.Cleanup(cleanupContext); err != nil {
			t.Errorf("Cleanup() error = %v", err)
		}
	}()
	outcome, executeErr := prepared.Execute(ctx)
	output, collectErr := prepared.Collect(ctx)
	if executeErr != nil {
		t.Fatalf("Execute() error = %v; stdout=%q stderr=%q; Collect() error = %v", executeErr, output.Stdout, output.Stderr, collectErr)
	}
	if collectErr != nil {
		t.Fatalf("Collect() error = %v", collectErr)
	}
	if outcome.Failure != nil {
		t.Fatalf("Execute() failure = %#v; stdout=%q stderr=%q", outcome.Failure, output.Stdout, output.Stderr)
	}
	if !strings.Contains(output.Stdout, "gvisor-smoke-ok") {
		t.Fatalf("sandbox output did not confirm containment checks; stdout=%q stderr=%q", output.Stdout, output.Stderr)
	}
}
