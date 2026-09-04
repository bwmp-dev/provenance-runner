//go:build linux

package gvisor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSystemdLauncherExecutesRunscAndLeavesTrustedMarker(t *testing.T) {
	marker := filepath.Join(t.TempDir(), systemdLaunchMarker)
	scopeRoot := "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice"
	unit := "provenance-0123456789abcdef0123456789abcdef"
	expectedScope := systemdCgroupPath(scopeRoot, unit)
	execCalled := false
	code := runSystemdLauncher(
		[]string{"--marker", marker, "--scope-root", scopeRoot, "--unit", unit, "--", "/bin/sh", "-c", "exit 7"},
		io.Discard,
		func() (string, bool) { return strings.TrimPrefix(expectedScope, "/sys/fs/cgroup"), true },
		func(path string) (os.FileInfo, error) {
			if path != expectedScope {
				t.Fatalf("stat path = %q, want %q", path, expectedScope)
			}
			return directoryInfo{name: filepath.Base(path)}, nil
		},
		func(path string, args, _ []string) error {
			execCalled = true
			if path != "/bin/sh" || strings.Join(args, " ") != "/bin/sh -c exit 7" {
				t.Fatalf("exec = %q %#v", path, args)
			}
			return nil
		},
	)
	if code != 0 || !execCalled {
		t.Fatalf("launcher code = %d, exec called = %t", code, execCalled)
	}
	if err := validateSystemdLaunchMarker(marker, expectedScope); err != nil {
		t.Fatalf("validateSystemdLaunchMarker() error = %v", err)
	}
}

func TestSystemdLauncherRemovesMarkerWhenExecFails(t *testing.T) {
	marker := filepath.Join(t.TempDir(), systemdLaunchMarker)
	var stderr bytes.Buffer
	scopeRoot := "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice"
	unit := "provenance-0123456789abcdef0123456789abcdef"
	expectedScope := systemdCgroupPath(scopeRoot, unit)
	code := runSystemdLauncher(
		[]string{"--marker", marker, "--scope-root", scopeRoot, "--unit", unit, "--", "/definitely/missing/runsc"},
		&stderr,
		func() (string, bool) { return strings.TrimPrefix(expectedScope, "/sys/fs/cgroup"), true },
		func(string) (os.FileInfo, error) { return directoryInfo{name: unit + ".scope"}, nil },
		func(string, []string, []string) error { return os.ErrNotExist },
	)
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

type directoryInfo struct{ name string }

func (info directoryInfo) Name() string  { return info.name }
func (directoryInfo) Size() int64        { return 0 }
func (directoryInfo) Mode() os.FileMode  { return os.ModeDir | 0o700 }
func (directoryInfo) ModTime() time.Time { return time.Time{} }
func (directoryInfo) IsDir() bool        { return true }
func (directoryInfo) Sys() any           { return nil }
