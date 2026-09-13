//go:build linux

// Trusted disposable controller, not a production privileged endpoint.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
)

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "owned Sentry namespace handoff failed")
		os.Exit(1)
	}
}

func run() error {
	fail := errors.New("disposable namespace handoff unavailable")
	if len(os.Args) != 1 || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		return fail
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return fail
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		return fail
	}
	if syscall.Setgroups([]int{}) != nil {
		return fail
	}
	cmd := exec.Command("/usr/local/bin/network-sentry-fixture", "child")
	cmd.Env = []string{"PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1"}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		return fail
	}
	defer input.Close()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 65532, Size: 1}, {ContainerID: 65534, HostID: 65533, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 65532, Size: 1}, {ContainerID: 65534, HostID: 65533, Size: 1}},
		Credential:  &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}, GidMappingsEnableSetgroups: false, Pdeathsig: syscall.SIGKILL,
	}
	if cmd.Start() != nil {
		return fail
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	const job = "10000000-0000-4000-8000-000000000001"
	identity, err := networkpolicy.RetainMappedChild(job, cmd.Process, networkpolicy.MappedIdentity{UID: 65532, GID: 65532, OverflowUID: 65533, OverflowGID: 65533})
	if err != nil {
		return fail
	}
	defer identity.Close()
	namespace, err := identity.NetworkForJob(job)
	if err != nil {
		return fail
	}
	defer namespace.Close()
	reference := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), namespace.Fd())
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"namespacePID": cmd.Process.Pid, "networkReference": reference}) != nil {
		return fail
	}
	var barrier [1]byte
	if _, err := io.ReadFull(os.Stdin, barrier[:]); err != nil || barrier[0] != 's' || identity.Validate(job) != nil {
		return fail
	}
	if _, err := input.Write(barrier[:]); err != nil {
		return fail
	}
	// Only the fixture's bounded phase commands follow. Parent exit kills the
	// mapped child; descriptor teardown does not pretend that workload exit did.
	go func() { _, _ = io.Copy(input, os.Stdin); _ = input.Close() }()
	err = cmd.Wait()
	waited = true
	if err != nil {
		return fail
	}
	return nil
}
