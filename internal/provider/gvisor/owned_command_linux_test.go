//go:build linux

package gvisor

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestOwnedMeasuredCommandRefusesUnownedLaunch(t *testing.T) {
	for _, cmd := range []*exec.Cmd{nil, exec.Command("/bin/true"), exec.Command("/proc/self/fd/5", RouterChildCommand)} {
		if done, err := startOwnedMeasuredCommand(cmd); done != nil || err == nil {
			t.Fatal("unowned launch admitted")
		}
	}
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, role := range []string{RouterChildCommand, MeasuredNetworkChildCommand, "arbitrary-command"} {
		cmd := exec.Command("/proc/self/fd/5", role)
		cmd.ExtraFiles = []*os.File{nil, nil, f}
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, UseCgroupFD: true}
		if done, err := startOwnedMeasuredCommand(cmd); done != nil || err == nil || cmd.Process != nil {
			t.Fatal("non-executable descriptor admitted")
		}
	}
}
