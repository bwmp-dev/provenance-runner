//go:build linux

package gvisor

import (
	"bytes"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func TestNamespaceFailureDiagnosticIsClosed(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{{fmt.Errorf("private marker: %w", syscall.EPERM), "permission"}, {syscall.EAGAIN, "resources"}, {fmt.Errorf("private marker"), "other"}} {
		if got := namespaceFailureCategory(test.err); got != test.want {
			t.Fatalf("unexpected safe category %q", got)
		}
	}
}

func TestMeasurementRequiresAggregateSystemdBoundary(t *testing.T) {
	provider, runner, _ := testProvider(t)
	config := provider.config
	config.RootFSImagePath = "/not-opened/image.squashfs"
	config.MeasuredRuntimeMode = "embedded-executable"
	if _, err := newProvider(config, runner); err == nil || !strings.Contains(err.Error(), "systemd-user accounting boundary") {
		t.Fatal("measured launcher allowed outside aggregate systemd boundary")
	}
	config.RootFSImagePath = ""
	config.MeasuredRuntimeMode = ""
	if _, err := newProvider(config, runner); err != nil {
		t.Fatal("legacy provider changed:", err)
	}
}

func TestMeasuredLauncherRejectsHostileInputsWithoutEcho(t *testing.T) {
	for _, args := range [][]string{nil, {"secret-value"}, {"/proc/123/fd/3", "/proc/123/fd/4", "/secret-value", "/proc/123/fd/7", "/tmp/.measured-root", "bad", "--"}} {
		var output bytes.Buffer
		if RunMeasuredLauncher(args, &output) != runscFailureExitCode || strings.Contains(output.String(), "secret-value") {
			t.Fatal("unsafe launcher input handling")
		}
		output.Reset()
		if RunMeasuredChild(args, &output) != runscFailureExitCode || strings.Contains(output.String(), "secret-value") {
			t.Fatal("unsafe child input handling")
		}
	}
}

func TestEmbeddedModeRejectsPolicyOverrides(t *testing.T) {
	t.Setenv("GVISOR_SIDECAR_BINARIES_DIR", "")
	t.Setenv("GVISOR_ENFORCE_RELEASE", "")
	if !embeddedOptions([]string{"--network=none", "--rootless=true", "run", "--bundle=/fixture", "fixture"}) {
		t.Fatal("ordinary run rejected")
	}
	for _, args := range [][]string{nil, {"restore"}, {"run"}, {"--network=plugin", "run"}, {"--network=none", "--network=none", "run"}, {"--network=none", "run", "--network=host"}, {"--network=none", "--sidecar-usage-policy=STRICT", "run"}, {"--network=none", "run", "--sidecar-usage-policy=DEFAULT"}, {"--network=none", "--sidecar-release-enforcement-policy=SKIP", "run"}} {
		if embeddedOptions(append([]string{"--rootless=true"}, args...)) {
			t.Fatal("incompatible helper policy accepted")
		}
	}
	for _, variable := range []string{"GVISOR_SIDECAR_BINARIES_DIR", "GVISOR_ENFORCE_RELEASE"} {
		t.Run(variable, func(t *testing.T) {
			t.Setenv(variable, "operator-selected")
			if embeddedOptions([]string{"--network=none", "--rootless=true", "run"}) {
				t.Fatal("operator policy silently overridden")
			}
		})
	}
}

func TestMeasuredRootlessArgumentsAndConflicts(t *testing.T) {
	t.Setenv("GVISOR_SIDECAR_BINARIES_DIR", "")
	t.Setenv("GVISOR_ENFORCE_RELEASE", "")
	provider, _, _ := testProvider(t)
	for _, argument := range provider.runArguments("run", "fixture") {
		if strings.HasPrefix(argument, "--rootless") {
			t.Fatal("legacy arguments changed")
		}
	}
	provider.config.RootFSImagePath = "/fixture/image"
	provider.config.MeasuredRuntimeMode = "embedded-executable"
	provider.config.CgroupDriver = CgroupDriverSystemdUser
	args := provider.runArguments("run", "fixture")
	if !embeddedOptions(args) {
		t.Fatal("actual measured provider arguments rejected")
	}
	for _, conflict := range []string{"--rootless", "--rootless=false", "--rootless=true", "--rootless=1"} {
		if embeddedOptions(append([]string{conflict}, args...)) || embeddedOptions(append(args[:len(args):len(args)], conflict)) {
			t.Fatal("duplicate or conflicting rootless option accepted")
		}
	}
	for _, args := range [][]string{{"--network=none", "run"}, {"--network=none", "--rootless=false", "run"}, {"--network=none", "run", "--rootless=true"}} {
		if embeddedOptions(args) {
			t.Fatal("missing or misplaced rootless option accepted")
		}
	}
}

func TestMeasuredNamespaceRequiresExactlyOneCallerMapping(t *testing.T) {
	if !singleCallerMapping([]byte("         0       1000          1\n")) {
		t.Fatal("valid caller mapping rejected")
	}
	for _, mapping := range []string{"", "0 0 1", "0 1000 2", "1 1000 1", "0 1000 1\n1 1001 1", "0 4294967295 1", "0 -1 1"} {
		if singleCallerMapping([]byte(mapping)) {
			t.Fatal("unsafe mapping accepted")
		}
	}
}
