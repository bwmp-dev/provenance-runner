package main

import (
	"context"
	"errors"
	"fmt"
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

func TestLocalHostileFixtureOptInIsStrict(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
		valid bool
	}{
		{value: "", valid: true},
		{value: "false", valid: true},
		{value: "true", want: true, valid: true},
		{value: "TRUE"},
		{value: "1"},
		{value: " true"},
		{value: "yes"},
	} {
		t.Run(fmt.Sprintf("value_%q", test.value), func(t *testing.T) {
			got, err := localHostileFixturesOptIn(func(name string) string {
				if name == localHostileFixturesEnvironment {
					return test.value
				}
				return ""
			})
			if (err == nil) != test.valid || got != test.want {
				t.Fatalf("localHostileFixturesOptIn() = %v, %v", got, err)
			}
		})
	}
}

func TestConnectedRegistryDoesNotReadLocalHostileFixtureOptIn(t *testing.T) {
	registry, err := registryForProvider(context.Background(), "development-process", func(name string) string {
		if name == localHostileFixturesEnvironment {
			return "true"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("registryForProvider() error = %v", err)
	}
	if err := registry.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
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

func TestPaperRegistryImmediatelyRemovesOwnedCrashWorkspaceWhileLocked(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("gVisor provider construction requires Linux")
	}
	values := paperEnvironment(t)
	owned := filepath.Join(values["PROVENANCE_WORKSPACE_ROOT"], "provenance-job-crashed")
	if err := os.Mkdir(owned, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := fmt.Sprintf(`{"version":1,"jobId":"attempt-1","createdAt":%q}`, time.Now().UTC().Format(time.RFC3339Nano))
	if err := os.WriteFile(filepath.Join(owned, ".provenance-workspace.json"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}

	registry, err := registryForProvider(context.Background(), "paper", func(name string) string { return values[name] })
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if _, err := os.Stat(owned); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned crash workspace remains: %v", err)
	}
}

func TestPaperRegistriesWithSharedWorkspaceAndDistinctBundlesContendBeforeCleanup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("gVisor provider construction requires Linux")
	}
	firstValues := paperEnvironment(t)
	first, err := registryForProvider(context.Background(), "paper", func(name string) string { return firstValues[name] })
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	owned := filepath.Join(firstValues["PROVENANCE_WORKSPACE_ROOT"], "provenance-job-active")
	if err := os.Mkdir(owned, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := fmt.Sprintf(`{"version":1,"jobId":"attempt-1","createdAt":%q}`, time.Now().UTC().Format(time.RFC3339Nano))
	if err := os.WriteFile(filepath.Join(owned, ".provenance-workspace.json"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}

	secondValues := make(map[string]string, len(firstValues))
	for name, value := range firstValues {
		secondValues[name] = value
	}
	secondValues["PROVENANCE_GVISOR_BUNDLE_ROOT"] = filepath.Join(filepath.Dir(firstValues["PROVENANCE_GVISOR_BUNDLE_ROOT"]), "bundles-second")
	secondValues["PROVENANCE_GVISOR_STATE_ROOT"] = filepath.Join(filepath.Dir(firstValues["PROVENANCE_GVISOR_STATE_ROOT"]), "state-second")
	_, err = registryForProvider(context.Background(), "paper", func(name string) string { return secondValues[name] })
	if !errors.Is(err, instancelock.ErrAlreadyHeld) {
		t.Fatalf("shared workspace contention error = %v, want ErrAlreadyHeld", err)
	}
	if _, err := os.Stat(owned); err != nil {
		t.Fatalf("contending initialization changed active workspace: %v", err)
	}

	partialPath := filepath.Join(secondValues["PROVENANCE_GVISOR_BUNDLE_ROOT"], ".provenance-runner.lock")
	partial, err := instancelock.Acquire(partialPath)
	if err != nil {
		t.Fatalf("bundle lock was not released after workspace contention: %v", err)
	}
	if err := partial.Close(); err != nil {
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
	for _, root := range []string{values["PROVENANCE_GVISOR_BUNDLE_ROOT"], values["PROVENANCE_WORKSPACE_ROOT"]} {
		lock, err := instancelock.Acquire(filepath.Join(root, ".provenance-runner.lock"))
		if err != nil {
			t.Fatalf("lock for %q remained held after setup failure: %v", root, err)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
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
		"PROVENANCE_PAPER_PROBE_SHA256":                        "abbccf45831ef998466542b19169731b9ec4f8a6c3525fce4d7a2c0b5f4b4b43",
		"PROVENANCE_PAPER_PROBE_SIZE_BYTES":                    "478837",
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
