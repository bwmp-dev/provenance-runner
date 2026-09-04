//go:build linux

package gvisor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdLauncherExecutesRunscAndLeavesTrustedMarker(t *testing.T) {
	marker := filepath.Join(t.TempDir(), systemdLaunchMarker)
	command := exec.Command(
		os.Args[0],
		SystemdLauncherCommand,
		"--marker", marker,
		"--",
		"/bin/sh", "-c", "exit 7",
	)
	err := command.Run()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 7 {
		t.Fatalf("launcher exit = %v, want child exit 7", err)
	}
	if err := validateSystemdLaunchMarker(marker); err != nil {
		t.Fatalf("validateSystemdLaunchMarker() error = %v", err)
	}
}

func TestSystemdLauncherRemovesMarkerWhenExecFails(t *testing.T) {
	marker := filepath.Join(t.TempDir(), systemdLaunchMarker)
	var stderr bytes.Buffer
	code := RunSystemdLauncher([]string{"--marker", marker, "--", "/definitely/missing/runsc"}, &stderr)
	if code != runscFailureExitCode {
		t.Fatalf("RunSystemdLauncher() = %d, want %d", code, runscFailureExitCode)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed exec marker still exists: %v", err)
	}
	if !strings.Contains(stderr.String(), "execute runsc from systemd scope") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestSystemdLauncherRejectsInvalidArguments(t *testing.T) {
	if code := RunSystemdLauncher([]string{"--marker", "relative", "--", "/bin/true"}, io.Discard); code != runscFailureExitCode {
		t.Fatalf("RunSystemdLauncher() = %d, want %d", code, runscFailureExitCode)
	}
}
