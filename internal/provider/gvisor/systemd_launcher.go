package gvisor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

const (
	SystemdLauncherCommand = "__gvisor-systemd-launch"
	systemdLaunchMarker    = ".provenance-systemd-launched"
)

// RunSystemdLauncher is the trusted, hidden child entrypoint used after
// systemd-run has placed the process in the bounded job scope. It records that
// the scope launch completed and then replaces itself with runsc, preserving
// runsc's exit status without adding a process to the outer PID reserve.
func RunSystemdLauncher(arguments []string, stderr io.Writer) int {
	return runSystemdLauncher(arguments, stderr, currentUnifiedCgroup, os.Stat, syscall.Exec)
}

func runSystemdLauncher(arguments []string, stderr io.Writer, current func() (string, bool), stat func(string) (os.FileInfo, error), execve func(string, []string, []string) error) int {
	if runtime.GOOS != "linux" {
		fmt.Fprintln(stderr, "systemd gVisor launcher requires Linux")
		return runscFailureExitCode
	}
	if len(arguments) < 8 || arguments[0] != "--marker" || arguments[2] != "--scope-root" || arguments[4] != "--unit" || arguments[6] != "--" || !filepath.IsAbs(arguments[1]) || !filepath.IsAbs(arguments[3]) || !validContainerID(arguments[5]) || !filepath.IsAbs(arguments[7]) {
		fmt.Fprintln(stderr, "invalid systemd gVisor launcher arguments")
		return runscFailureExitCode
	}
	marker := filepath.Clean(arguments[1])
	scopeRoot := filepath.Clean(arguments[3])
	expectedScope := systemdCgroupPath(scopeRoot, arguments[5])
	relative, ok := current()
	currentScope := filepath.Clean(filepath.Join("/sys/fs/cgroup", relative))
	if !ok || filepath.Base(scopeRoot) != "app.slice" || (currentScope != expectedScope && !strings.HasPrefix(currentScope, expectedScope+string(filepath.Separator))) {
		fmt.Fprintln(stderr, "systemd gVisor launcher is outside the expected scope")
		return runscFailureExitCode
	}
	if info, err := stat(expectedScope); err != nil || !info.IsDir() {
		fmt.Fprintln(stderr, "systemd gVisor scope is not observable")
		return runscFailureExitCode
	}
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "create systemd gVisor launch marker:", err)
		return runscFailureExitCode
	}
	markerContent := "systemd-user-scope:" + expectedScope + "\n"
	if _, err = file.WriteString(markerContent); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = syncDirectory(filepath.Dir(marker))
	}
	if err != nil {
		_ = os.Remove(marker)
		fmt.Fprintln(stderr, "persist systemd gVisor launch marker:", err)
		return runscFailureExitCode
	}
	runscPath := arguments[7]
	if err := execve(runscPath, arguments[7:], os.Environ()); err != nil {
		removeErr := os.Remove(marker)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			fmt.Fprintln(stderr, "remove failed systemd gVisor launch marker:", removeErr)
		}
		fmt.Fprintln(stderr, "execute runsc from systemd scope:", err)
		return runscFailureExitCode
	}
	return 0
}

func validateSystemdLaunchMarker(path, expectedScope string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	markerContent := "systemd-user-scope:" + expectedScope + "\n"
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != int64(len(markerContent)) {
		return errors.New("invalid systemd gVisor launch marker")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(content) != markerContent {
		return errors.New("invalid systemd gVisor launch marker content")
	}
	return nil
}
