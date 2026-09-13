//go:build linux

package networkpolicy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMappedChildNamespaceInvalidInputs(t *testing.T) {
	for _, mapping := range []MappedIdentity{{}, {65532, 65532, 65532, 65533}, {65532, 65532, 65533, 65532}, {65532, 65532, ^uint32(0), 65533}} {
		if validMappedIdentity(mapping) {
			t.Fatal("unsafe mapping accepted")
		}
	}
	if s, err := RetainMappedChild("invalid", nil, MappedIdentity{}); s != nil || err != ErrNamespace {
		t.Fatal("invalid namespace input")
	}
	var s *ChildNamespaces
	if s.Validate("job") != ErrNamespace {
		t.Fatal("nil namespace accepted")
	}
	if f, err := s.NetworkForJob("job"); f != nil || err != ErrNamespace {
		t.Fatal("nil namespace duplicated")
	}
	if s.Close() != nil {
		t.Fatal("nil close failed")
	}
}

// This subprocess is only launched inside the separately prepared disposable
// container. It inherits no host mounts, interfaces, credentials or job payload.
func TestMappedChildNamespaceProcess(t *testing.T) {
	mode := os.Getenv("PROVENANCE_NAMESPACE_TEST_CHILD")
	if mode == "" {
		t.Skip("owned subprocess entry only")
	}
	if os.Getuid() != 0 || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		os.Exit(2)
	}
	if mode == "grandchild" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestMappedChildNamespaceProcess$")
		cmd.Env = []string{"PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1", "PROVENANCE_NAMESPACE_TEST_CHILD=holder"}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if cmd.Start() != nil {
			os.Exit(2)
		}
		fmt.Printf("grandchild:%d\n", cmd.Process.Pid)
		if cmd.Wait() != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	if mode != "holder" {
		os.Exit(2)
	}
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func TestMappedChildNamespaceKernelOwnership(t *testing.T) {
	if os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		t.Skip("explicit disposable kernel fixture required")
	}
	if os.Getuid() != 0 {
		t.Fatal("disposable root controller required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container required")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("fixture must have network=none")
	}
	// Drop only this disposable test process's groups before creating mappings;
	// setgroups is permanently denied in each child user namespace.
	// Go's syscall wrapper updates all runtime threads; the raw unix syscall
	// changes only the current thread and would make fork inheritance depend on
	// which scheduler thread happened to launch the next child.
	if syscall.Setgroups([]int{}) != nil {
		t.Fatal("cannot drop fixture groups")
	}
	mapping := MappedIdentity{UID: 65532, GID: 65532, OverflowUID: 65533, OverflowGID: 65533}
	job := "10000000-0000-4000-8000-000000000001"
	otherJob := "20000000-0000-4000-8000-000000000001"
	spawn := func(t *testing.T, freshNetwork bool, mode string) (*exec.Cmd, *os.File, *bufio.Reader) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMappedChildNamespaceProcess$")
		cmd.Env = []string{"PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1", "PROVENANCE_NAMESPACE_TEST_CHILD=" + mode}
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdin = read
		output, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		flags := uintptr(unix.CLONE_NEWUSER | unix.CLONE_NEWNS)
		if freshNetwork {
			flags |= unix.CLONE_NEWNET
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: flags,
			UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 65532, Size: 1}, {ContainerID: 65534, HostID: 65533, Size: 1}},
			GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 65532, Size: 1}, {ContainerID: 65534, HostID: 65533, Size: 1}},
			GidMappingsEnableSetgroups: false, Credential: &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL}
		if err := cmd.Start(); err != nil {
			read.Close()
			write.Close()
			cancel()
			t.Fatal("mapped child unavailable")
		}
		read.Close()
		t.Cleanup(func() { write.Close(); cancel(); _ = cmd.Wait() })
		return cmd, write, bufio.NewReaderSize(output, 256)
	}
	ready := func(t *testing.T, reader *bufio.Reader) {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil || line != "ready\n" {
			t.Fatal("mapped child readiness missing")
		}
	}
	t.Run("retained-job-and-living-child", func(t *testing.T) {
		cmd, control, out := spawn(t, true, "holder")
		ready(t, out)
		s, err := RetainMappedChild(job, cmd.Process, mapping)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.Validate(job); err != nil {
			t.Fatal(err)
		}
		f, err := s.NetworkForJob(job)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		actual, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		defer actual.Close()
		if !sameNamespace(f, actual, unix.CLONE_NEWNET) {
			t.Fatal("duplicate did not retain exact child kernel object")
		}
		if s.Validate(otherJob) != ErrNamespace {
			t.Fatal("foreign job accepted")
		}
		if other, err := s.NetworkForJob(otherJob); other != nil || err != ErrNamespace {
			t.Fatal("foreign job obtained namespace")
		}
		control.Close()
		if cmd.Wait() != nil {
			t.Fatal("owned child failed to stop")
		}
		if s.Validate(job) != ErrNamespace {
			t.Fatal("exited child retained authority")
		}
		if other, err := s.NetworkForJob(job); other != nil || err != ErrNamespace {
			t.Fatal("exited child duplicated namespace")
		}
	})
	t.Run("wrong-mapping", func(t *testing.T) {
		cmd, _, out := spawn(t, true, "holder")
		ready(t, out)
		wrong := mapping
		wrong.OverflowUID = 65531
		if s, err := RetainMappedChild(job, cmd.Process, wrong); s != nil || err != ErrNamespace {
			t.Fatal("foreign mapping accepted")
		}
		before, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal("descriptor inventory unavailable")
		}
		for range 8 {
			if s, err := RetainMappedChild(job, cmd.Process, wrong); s != nil || err != ErrNamespace {
				t.Fatal("foreign mapping accepted on replay")
			}
		}
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(before) != len(after) {
			t.Fatal("refused namespace capture leaked descriptors")
		}
	})
	t.Run("close-references-only", func(t *testing.T) {
		cmd, _, out := spawn(t, true, "holder")
		ready(t, out)
		s, err := RetainMappedChild(job, cmd.Process, mapping)
		if err != nil {
			t.Fatal(err)
		}
		if s.Close() != nil || s.Close() != nil {
			t.Fatal("reference cleanup failed")
		}
		if cmd.Process.Signal(syscall.Signal(0)) != nil {
			t.Fatal("reference cleanup unexpectedly killed child")
		}
		if s.Validate(job) != ErrNamespace {
			t.Fatal("closed namespace owner validated")
		}
		if f, err := s.NetworkForJob(job); f != nil || err != ErrNamespace {
			t.Fatal("closed owner duplicated namespace")
		}
	})
	t.Run("inherited-controller-network", func(t *testing.T) {
		cmd, _, out := spawn(t, false, "holder")
		ready(t, out)
		if s, err := RetainMappedChild(job, cmd.Process, mapping); s != nil || err != ErrNamespace {
			t.Fatal("controller network adopted")
		}
	})
	t.Run("supplementary-group-refused", func(t *testing.T) {
		if syscall.Setgroups([]int{7}) != nil {
			t.Fatal("cannot establish synthetic extra group")
		}
		t.Cleanup(func() {
			if syscall.Setgroups([]int{}) != nil {
				t.Error("cannot restore disposable groups")
			}
		})
		cmd, _, out := spawn(t, true, "holder")
		ready(t, out)
		if s, err := RetainMappedChild(job, cmd.Process, mapping); s != nil || err != ErrNamespace {
			t.Fatal("supplementary group accepted")
		}
	})
	t.Run("not-direct-child", func(t *testing.T) {
		_, _, out := spawn(t, true, "grandchild")
		// The two writers may report in either order, but both bounded records
		// must be present before checking the real grandchild's kernel identity.
		var pid int
		seenReady := false
		for range 2 {
			line, err := out.ReadString('\n')
			if err != nil || len(line) > 64 {
				t.Fatal("grandchild readiness unavailable")
			}
			if line == "ready\n" {
				seenReady = true
				continue
			}
			if !strings.HasPrefix(line, "grandchild:") {
				t.Fatal("invalid grandchild report")
			}
			pid, err = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "grandchild:")))
			if err != nil {
				t.Fatal("invalid grandchild identity")
			}
		}
		if !seenReady || pid <= 1 {
			t.Fatal("grandchild not ready")
		}
		process, err := os.FindProcess(pid)
		if err != nil {
			t.Fatal("grandchild unavailable")
		}
		defer process.Release()
		if s, err := RetainMappedChild(job, process, mapping); s != nil || err != ErrNamespace {
			t.Fatal("foreign parent accepted")
		}
	})
}
