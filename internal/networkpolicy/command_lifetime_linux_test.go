//go:build linux

package networkpolicy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestRetainedCommandLifecycleProcess(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" {
		t.Skip("closed subprocess entry only")
	}
	mode := os.Args[len(os.Args)-1]
	if os.Getuid() != 0 {
		os.Exit(2)
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		os.Exit(2)
	}
	current, err := os.Stat("/proc/self/ns/net")
	parent, other := os.Stat("/proc/1/ns/net")
	if err != nil || other != nil || os.SameFile(current, parent) {
		os.Exit(2)
	}
	if mode == "tool" {
		var signal int32
		if unix.Prctl(unix.PR_GET_PDEATHSIG, uintptr(unsafe.Pointer(&signal)), 0, 0, 0) != nil || signal != int32(unix.SIGKILL) {
			os.Exit(2)
		}
		ready := os.NewFile(6, "owned-command-ready")
		if _, err := fmt.Fprintf(ready, "%d\n", os.Getpid()); err != nil {
			os.Exit(2)
		}
		ready.Close()
		time.Sleep(10 * time.Second)
		os.Exit(2)
	}
	if mode != "controller" || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		os.Exit(2)
	}
	load := func(path string) ProtectedRouteTool {
		file, err := os.Open(path)
		if err != nil {
			os.Exit(2)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			os.Exit(2)
		}
		return ProtectedRouteTool{File: file, SHA256: [32]byte(hash.Sum(nil))}
	}
	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		os.Exit(2)
	}
	network, err := os.Open("/proc/self/ns/net")
	if err != nil {
		os.Exit(2)
	}
	nsTool, self := load(nsenter), load(os.Args[0])
	_, err = executeRetainedTool(context.Background(), network, nsTool, self, []*os.File{os.NewFile(3, "owned-command-ready")}, "", "-test.run=^TestRetainedCommandLifecycleProcess$", "--", "tool")
	fmt.Fprintln(os.Stderr, "owned fixture command result", err)
	os.Exit(2)
}

func TestRetainedCommandControllerDeath(t *testing.T) {
	if os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		t.Skip("explicit disposable kernel fixture required")
	}
	if os.Getuid() != 0 {
		t.Fatal("disposable root required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container required")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("network-none fixture required")
	}
	var prior int32
	if unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&prior)), 0, 0, 0) != nil || unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != nil {
		t.Fatal("subreaper unavailable")
	}
	defer unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(prior), 0, 0, 0)
	ready, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	defer writer.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestRetainedCommandLifecycleProcess$", "--", "controller")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1"}
	command.ExtraFiles = []*os.File{writer}
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	if command.Start() != nil {
		t.Fatal("controller start")
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	writer.Close()
	if ready.SetReadDeadline(time.Now().Add(2*time.Second)) != nil {
		t.Fatal("ready deadline")
	}
	line, err := bufio.NewReaderSize(ready, 32).ReadString('\n')
	if err != nil || len(line) > 12 {
		t.Fatal("command did not prove death signal")
	}
	pid, err := strconv.Atoi(line[:len(line)-1])
	if err != nil || pid <= 1 {
		t.Fatal("command identity")
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal("command pidfd")
	}
	defer unix.Close(pidfd)
	reaped := false
	defer func() {
		if reaped {
			return
		}
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		var status unix.WaitStatus
		_, _ = unix.Wait4(pid, &status, 0, nil)
	}()
	if command.Process.Kill() != nil {
		t.Fatal("controller death")
	}
	_ = command.Wait()
	// This deadline is shorter than the actuator's three-second timeout. Only
	// kernel parent-death cleanup can satisfy it after the controller is gone.
	deadline := time.Now().Add(time.Second)
	for {
		poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		_, err := unix.Poll(poll, 100)
		if err != nil && err != unix.EINTR {
			t.Fatal("command liveness")
		}
		if poll[0].Revents&unix.POLLIN != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retained command survived controller death")
		}
	}
	var status unix.WaitStatus
	if waited, err := unix.Wait4(pid, &status, 0, nil); err != nil || waited != pid || !status.Signaled() || status.Signal() != unix.SIGKILL {
		t.Fatal("command not killed and reaped")
	}
	reaped = true
}
