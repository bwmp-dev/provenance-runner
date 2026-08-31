package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/instancelock"
)

func TestPaperRegistryFailsBeforeExecutionWhenOperatorPinsAreMissing(t *testing.T) {
	_, err := registryForProvider(context.Background(), "paper", func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "PROVENANCE_PAPER_PROBE_URI") {
		t.Fatalf("registryForProvider() error = %v", err)
	}
}

func TestPaperRegistryRejectsBadOperatorPinBeforeRuntimeSetup(t *testing.T) {
	values := map[string]string{
		"PROVENANCE_PAPER_PROBE_URI":        "https://artifacts.example.com/probe.jar",
		"PROVENANCE_PAPER_PROBE_SHA256":     "bad",
		"PROVENANCE_PAPER_PROBE_SIZE_BYTES": "1",
	}
	_, err := registryForProvider(context.Background(), "paper", func(name string) string { return values[name] })
	if err == nil || !strings.Contains(err.Error(), "PROVENANCE_PAPER_PROBE_SHA256") {
		t.Fatalf("registryForProvider() error = %v", err)
	}
}

func TestOperatorCatalogRejectsAWellFormedButUnpinnedProbe(t *testing.T) {
	values := paperEnvironment(t)
	values["PROVENANCE_PAPER_PROBE_SHA256"] = strings.Repeat("a", 64)
	if _, err := operatorCatalog(func(name string) string { return values[name] }); err == nil || !strings.Contains(err.Error(), "must be probe 0.1.0") {
		t.Fatalf("operatorCatalog() error = %v", err)
	}
}

func TestPaperRegistrySelectsOperatorConfiguredProvider(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("gVisor provider construction requires Linux")
	}
	values := paperEnvironment(t)
	registry, err := registryForProvider(context.Background(), "paper", func(name string) string { return values[name] })
	if err != nil {
		t.Fatalf("registryForProvider() error = %v", err)
	}
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	provider, exists := registry.Provider("paper")
	if !exists || provider.Name() != "paper" {
		t.Fatalf("paper provider = %#v, %v", provider, exists)
	}
}

func TestPaperRegistryLockPreventsConcurrentReconciliation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("gVisor provider construction requires Linux")
	}
	values := paperEnvironment(t)
	first, err := registryForProvider(context.Background(), "paper", func(name string) string { return values[name] })
	if err != nil {
		t.Fatal(err)
	}
	activeBundle := filepath.Join(values["PROVENANCE_GVISOR_BUNDLE_ROOT"], "active-job")
	if err := os.Mkdir(activeBundle, 0o700); err != nil {
		t.Fatal(err)
	}
	metadata := `{"version":1,"containerId":"provenance-0123456789abcdef0123456789abcdef","phase":"prepared"}`
	if err := os.WriteFile(filepath.Join(activeBundle, ".provenance-gvisor.json"), []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(activeBundle, ".provenance-run-attempted"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = registryForProvider(context.Background(), "paper", func(name string) string { return values[name] })
	if !errors.Is(err, instancelock.ErrAlreadyHeld) {
		t.Fatalf("contending registry error = %v, want ErrAlreadyHeld", err)
	}
	if _, err := os.Stat(activeBundle); err != nil {
		t.Fatalf("active bundle changed during lock contention: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(activeBundle); err != nil {
		t.Fatal(err)
	}
	second, err := registryForProvider(context.Background(), "paper", func(name string) string { return values[name] })
	if err != nil {
		t.Fatalf("registry after release error = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPaperRegistryBoundsReconciliationAndReleasesLockOnFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("gVisor provider construction requires Linux")
	}
	values := paperEnvironment(t)
	if err := os.WriteFile(values["PROVENANCE_RUNSC_PATH"], []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	activeBundle := filepath.Join(values["PROVENANCE_GVISOR_BUNDLE_ROOT"], "abandoned-job")
	if err := os.MkdirAll(activeBundle, 0o700); err != nil {
		t.Fatal(err)
	}
	metadata := `{"version":1,"containerId":"provenance-0123456789abcdef0123456789abcdef","phase":"prepared"}`
	if err := os.WriteFile(filepath.Join(activeBundle, ".provenance-gvisor.json"), []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(activeBundle, ".provenance-run-attempted"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := registryForProvider(ctx, "paper", func(name string) string { return values[name] })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded reconciliation error = %v, want deadline exceeded", err)
	}
	lock, err := instancelock.Acquire(filepath.Join(values["PROVENANCE_GVISOR_BUNDLE_ROOT"], ".provenance-runner.lock"))
	if err != nil {
		t.Fatalf("lock remained held after setup failure: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func paperEnvironment(t *testing.T) map[string]string {
	t.Helper()
	root := t.TempDir()
	runsc := filepath.Join(root, "runsc")
	if err := os.WriteFile(runsc, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"PROVENANCE_PAPER_PROBE_URI":                           "https://artifacts.example.com/paper-probe.jar",
		"PROVENANCE_PAPER_PROBE_SHA256":                        "cc981edc49a1fc27a920c3e39415428d3897eb878e748a6ad2b708972ef6e082",
		"PROVENANCE_PAPER_PROBE_SIZE_BYTES":                    "462392",
		"PROVENANCE_PAPER_PREPARED_RUNTIME_URI":                "https://artifacts.example.com/prepared-runtime.tar.gz",
		"PROVENANCE_PAPER_PREPARED_RUNTIME_SHA256":             strings.Repeat("b", 64),
		"PROVENANCE_PAPER_PREPARED_RUNTIME_SIZE_BYTES":         "2048",
		"PROVENANCE_PAPER_PREPARED_RUNTIME_MAX_EXPANDED_BYTES": "4096",
		"PROVENANCE_WORKSPACE_ROOT":                            filepath.Join(root, "workspaces"),
		"PROVENANCE_CACHE_ROOT":                                filepath.Join(root, "cache"),
		"PROVENANCE_ARTIFACT_HOSTS":                            "artifacts.example.com",
		"PROVENANCE_RUNSC_PATH":                                runsc,
		"PROVENANCE_ROOTFS":                                    filepath.Join(root, "rootfs"),
		"PROVENANCE_ROOTFS_IDENTITY":                           "sha256:test-rootfs",
		"PROVENANCE_GVISOR_STATE_ROOT":                         filepath.Join(root, "state"),
		"PROVENANCE_GVISOR_BUNDLE_ROOT":                        filepath.Join(root, "bundles"),
	}
	for _, directory := range []string{values["PROVENANCE_WORKSPACE_ROOT"], values["PROVENANCE_ROOTFS"]} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return values
}
