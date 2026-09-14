//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	"golang.org/x/sys/unix"
)

// This fixture proves the actual measured mount/exec handoff in a fresh two-ID
// namespace. It intentionally has no WAN or route: it is not hosted network
// acceptance, authority enforcement, or a resource-boundary proof.
func TestMeasuredNetworkRootHandoff(t *testing.T) {
	root := os.Getenv("PROVENANCE_NETWORK_MEASUREMENT_FIXTURE_ROOT")
	if root == "" {
		t.Skip("disposable protected-image fixture not provisioned")
	}
	if root != "/tmp/provenance-runtime-fixture" || os.Getuid() != 0 {
		t.Fatal("unexpected fixture identity")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("fresh disposable container required")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("fixture requires network=none")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		t.Fatal("fixture must start with cleared supplementary groups")
	}
	ids := [2]int{1000, 1000}
	for i, name := range []string{"PROVENANCE_MEASUREMENT_FIXTURE_UID", "PROVENANCE_MEASUREMENT_FIXTURE_GID"} {
		if value := os.Getenv(name); value != "" {
			ids[i], err = strconv.Atoi(value)
			if err != nil || ids[i] < 1 || ids[i] > 63999 {
				t.Fatal("unexpected mapped fixture identity")
			}
		}
	}
	lease, err := runtimeidentity.Acquire(context.Background(), filepath.Join(root, "runsc"), filepath.Join(root, "mount"), filepath.Join(root, "image.squashfs"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	for _, token := range []string{"x", "s"} {
		t.Run("gate-"+token, func(t *testing.T) {
			job := "20000000-0000-4000-8000-000000000001"
			if token == "s" {
				job = "20000000-0000-4000-8000-000000000002"
			}
			bundle := filepath.Join(root, "work", job)
			privateRoot := filepath.Join(bundle, ".measured-root")
			for _, path := range []string{bundle, privateRoot} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(path, ids[0], ids[1]); err != nil {
					t.Fatal(err)
				}
			}
			spec := map[string]any{
				"ociVersion": "1.0.2", "root": map[string]any{"path": privateRoot, "readonly": true},
				"process": map[string]any{"terminal": false, "user": map[string]any{"uid": 65532, "gid": 65532}, "args": []string{"/fixture-test", "-test.run=^TestMeasurementGuestIdentity$", "-test.v"}, "env": []string{"PATH=/", "PROVENANCE_MEASUREMENT_GUEST=1"}, "cwd": "/", "noNewPrivileges": true},
				"linux":   map[string]any{"namespaces": []map[string]string{{"type": "pid"}, {"type": "mount"}, {"type": "network", "path": "/proc/self/ns/net"}, {"type": "ipc"}, {"type": "uts"}}},
			}
			encoded, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(bundle, "config.json")
			if err := os.WriteFile(config, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(config, ids[0], ids[1]); err != nil {
				t.Fatal(err)
			}
			var files []*os.File
			defer func() {
				for _, file := range files {
					file.Close()
				}
			}()
			for i, path := range []string{lease.RootPath(), lease.SandboxPath(), lease.RunnerPath(), lease.ImagePath(), lease.LoopPath(), "/proc/self/ns/net", "/proc/self/ns/mnt"} {
				flags := os.O_RDONLY
				if i == 0 {
					flags = unix.O_PATH | unix.O_DIRECTORY
				}
				file, err := os.OpenFile(path, flags, 0)
				if err != nil {
					t.Fatal(err)
				}
				files = append(files, file)
			}
			gate, release, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Close()
			defer release.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			args := []string{MeasuredNetworkChildCommand, job, strconv.Itoa(ids[0]), strconv.Itoa(ids[1]), strconv.Itoa(ids[0] + 1), strconv.Itoa(ids[1] + 1), privateRoot, lease.Snapshot().RootFS.SHA256, "embedded-executable"}
			child := exec.CommandContext(ctx, "/proc/self/fd/5", args...)
			child.ExtraFiles = append(files, gate)
			child.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
			child.SysProcAttr = &syscall.SysProcAttr{
				Cloneflags:                 unix.CLONE_NEWUSER | unix.CLONE_NEWNET | unix.CLONE_NEWNS,
				UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: ids[0], Size: 1}, {ContainerID: 65534, HostID: ids[0] + 1, Size: 1}},
				GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: ids[1], Size: 1}, {ContainerID: 65534, HostID: ids[1] + 1, Size: 1}},
				GidMappingsEnableSetgroups: false, Credential: &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL,
			}
			var output bytes.Buffer
			child.Stdout, child.Stderr = &output, &output
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
			owned, err := networkpolicy.RetainMappedChild(job, child.Process, networkpolicy.MappedIdentity{UID: uint32(ids[0]), GID: uint32(ids[1]), OverflowUID: uint32(ids[0] + 1), OverflowGID: uint32(ids[1] + 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer owned.Close()
			// No mount or execution may occur while the controller holds the gate.
			time.Sleep(50 * time.Millisecond)
			if _, err := os.Stat(filepath.Join(bundle, ".measured-sidecars")); !os.IsNotExist(err) {
				t.Fatal("execution preceded gate")
			}
			if _, err := release.Write([]byte(token)); err != nil {
				t.Fatal(err)
			}
			release.Close()
			err = child.Wait()
			if token == "x" {
				if err == nil || !strings.Contains(output.String(), "handoff refused: mapping") {
					t.Fatalf("unauthorized launch: %v %s", err, output.String())
				}
			} else if err != nil || !strings.Contains(output.String(), "--- PASS: TestMeasurementGuestIdentity") {
				t.Fatalf("actual measured network child failed: %v %s", err, output.String())
			}
			if err := lease.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
