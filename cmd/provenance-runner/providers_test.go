package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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

func TestPaperRegistrySelectsOperatorConfiguredProvider(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("gVisor provider construction requires Linux")
	}
	root := t.TempDir()
	runsc := filepath.Join(root, "runsc")
	if err := os.WriteFile(runsc, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"PROVENANCE_PAPER_PROBE_URI":                           "https://artifacts.example.com/paper-probe.jar",
		"PROVENANCE_PAPER_PROBE_SHA256":                        strings.Repeat("a", 64),
		"PROVENANCE_PAPER_PROBE_SIZE_BYTES":                    "1024",
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
	registry, err := registryForProvider(context.Background(), "paper", func(name string) string { return values[name] })
	if err != nil {
		t.Fatalf("registryForProvider() error = %v", err)
	}
	provider, exists := registry.Provider("paper")
	if !exists || provider.Name() != "paper" {
		t.Fatalf("paper provider = %#v, %v", provider, exists)
	}
}
