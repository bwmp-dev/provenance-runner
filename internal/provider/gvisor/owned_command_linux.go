//go:build linux

package gvisor

import (
	"errors"
	"os/exec"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// startOwnedMeasuredCommand keeps the thread that creates the child alive
// through Wait. Linux PDEATHSIG refers to that thread, not the Go process as a
// whole. The caller may return, migrate, or retire its own thread independently.
// Only the two internally constructed, cgroup-owned measured roles use this.
func startOwnedMeasuredCommand(cmd *exec.Cmd) (<-chan error, error) {
	if cmd == nil || cmd.Path != "/proc/self/fd/5" || len(cmd.Args) < 2 ||
		(cmd.Args[1] != RouterChildCommand && cmd.Args[1] != MeasuredNetworkChildCommand) ||
		cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL ||
		!cmd.SysProcAttr.UseCgroupFD || len(cmd.ExtraFiles) < 3 || cmd.ExtraFiles[2] == nil {
		return nil, ErrMeasuredNetworkLaunch
	}
	// Executing a privileged file can clear PDEATHSIG. The retained measured
	// executable must not acquire privileges through set-ID or file capabilities.
	fd := int(cmd.ExtraFiles[2].Fd())
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != 0 || stat.Mode&06022 != 0 || stat.Mode&0111 == 0 {
		return nil, ErrMeasuredNetworkLaunch
	}
	if _, err := unix.Fgetxattr(fd, "security.capability", nil); !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.EOPNOTSUPP) {
		return nil, ErrMeasuredNetworkLaunch
	}
	started := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(done)
		err := cmd.Start()
		started <- err
		if err == nil {
			done <- cmd.Wait()
		}
	}()
	if err := <-started; err != nil {
		return nil, err
	}
	return done, nil
}
