package gvisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReconcileDeletesOnlyOwnedAbandonedBundles(t *testing.T) {
	provider, runner, _ := testProvider(t)
	owned := prepareEnvironment(t, provider, validConfiguration(), 1024)
	foreign := filepath.Join(provider.config.BundleRoot, "foreign")
	invalid := filepath.Join(provider.config.BundleRoot, "invalid")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(invalid, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(invalid, metadataName), []byte(`{"version":1,"containerId":"../../victim"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := provider.Reconcile(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid ownership metadata") {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if _, err := os.Stat(owned.bundle); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("owned bundle remains: %v", err)
	}
	for _, path := range []string{foreign, invalid} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("unowned bundle %q changed: %v", path, err)
		}
	}
	commands := runner.commands()
	if len(commands) != 1 || commandVerb(commands[0].Args) != "delete" || commands[0].Args[len(commands[0].Args)-1] != owned.containerID {
		t.Errorf("runtime commands = %#v", commands)
	}
}

func TestReconcileRetainsBundleWhenRuntimeDeleteFails(t *testing.T) {
	provider, runner, _ := testProvider(t)
	owned := prepareEnvironment(t, provider, validConfiguration(), 1024)
	runner.run = func(context.Context, command) commandResult {
		return commandResult{Err: errors.New("runsc state unavailable")}
	}

	err := provider.Reconcile(context.Background())
	if err == nil || !strings.Contains(err.Error(), "runsc state unavailable") {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if _, err := os.Stat(owned.bundle); err != nil {
		t.Errorf("bundle removed despite failed delete: %v", err)
	}
}

func TestReconcileHonorsCancellationBetweenBundles(t *testing.T) {
	provider, runner, _ := testProvider(t)
	first := prepareEnvironment(t, provider, validConfiguration(), 1024)
	second := prepareEnvironment(t, provider, validConfiguration(), 1024)
	ctx, cancel := context.WithCancel(context.Background())
	runner.run = func(context.Context, command) commandResult {
		cancel()
		return successResult()
	}

	err := provider.Reconcile(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Reconcile() error = %v", err)
	}
	remaining := []bool{pathExists(first.bundle), pathExists(second.bundle)}
	if !reflect.DeepEqual(remaining, []bool{false, true}) && !reflect.DeepEqual(remaining, []bool{true, false}) {
		t.Errorf("bundle existence = %#v, want exactly one removed", remaining)
	}
	if len(runner.commands()) != 1 {
		t.Errorf("runtime command count = %d", len(runner.commands()))
	}
}

func TestReadMetadataRejectsTrailingValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), metadataName)
	if err := os.WriteFile(path, []byte(`{"version":1,"containerId":"provenance-0123456789abcdef0123456789abcdef"}{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMetadata(path); err == nil {
		t.Fatal("readMetadata() error = nil")
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
