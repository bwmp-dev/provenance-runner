//go:build linux

package runtimeidentity

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLeaseValidMappingRequiresExactCompleteReadOnlyImage(t *testing.T) {
	lease := &Lease{imageStat: unix.Stat_t{Dev: 2049, Ino: 12345}}
	exact := unix.LoopInfo64{Device: 2049, Inode: 12345, Flags: unix.LO_FLAGS_READ_ONLY}
	for _, test := range []struct {
		name   string
		change func(*unix.LoopInfo64)
		valid  bool
	}{
		{"exact full image", func(*unix.LoopInfo64) {}, true},
		{"nonzero offset", func(m *unix.LoopInfo64) { m.Offset = 1 }, false},
		{"nonzero size limit", func(m *unix.LoopInfo64) { m.Sizelimit = 1 }, false},
		{"encryption type", func(m *unix.LoopInfo64) { m.Encrypt_type = 1 }, false},
		{"encryption key size", func(m *unix.LoopInfo64) { m.Encrypt_key_size = 1 }, false},
		{"missing read only", func(m *unix.LoopInfo64) { m.Flags = 0 }, false},
		{"other flag is not read only", func(m *unix.LoopInfo64) { m.Flags = unix.LO_FLAGS_AUTOCLEAR }, false},
		{"wrong backing device", func(m *unix.LoopInfo64) { m.Device++ }, false},
		{"wrong backing inode", func(m *unix.LoopInfo64) { m.Inode++ }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			mapping := exact
			test.change(&mapping)
			if got := lease.validMapping(&mapping); got != test.valid {
				t.Fatalf("validMapping() = %t, want %t", got, test.valid)
			}
			if !lease.validMapping(&exact) {
				t.Fatal("exact baseline was mutated")
			}
		})
	}
}

func TestRunningExecutableReference(t *testing.T) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	before, err := hashObject(file, maximumExecutableBytes, true)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(reference(file), "-test.run=^$")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("exact executable reference failed: %v %s", err, output)
	}
	after, err := hashObject(file, maximumExecutableBytes, true)
	if err != nil || before != after {
		t.Fatal("retained executable changed")
	}
}

func TestRejectWrapperAndMutableRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrapper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := hashObject(file, maximumExecutableBytes, true); err == nil {
		t.Fatal("wrapper measured as executable")
	}
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := inspectMount(root); err == nil {
		t.Fatal("ordinary directory measured as SquashFS")
	}
}

// Executes only inside explicitly provisioned disposable loop/mount fixture.
func TestRuntimeMountFixture(t *testing.T) {
	root := os.Getenv("PROVENANCE_MEASUREMENT_FIXTURE_ROOT")
	if root == "" {
		t.Skip("disposable privileged fixture not provisioned")
	}
	if os.Geteuid() != 1000 || root != "/tmp/provenance-runtime-fixture" {
		t.Fatal("unexpected fixture identity")
	}
	lease, err := Acquire(context.Background(), filepath.Join(root, "runsc"), filepath.Join(root, "mount"), filepath.Join(root, "image.squashfs"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if !lease.Snapshot().Valid() {
		t.Fatal("invalid snapshot")
	}
	if err := lease.Validate(); err != nil {
		t.Fatal(err)
	}
	// Exercise the actual retained-object validator, not an independent matcher.
	originalMount := lease.mountID
	lease.mountID++
	if lease.Validate() == nil {
		t.Fatal("changed mount identity accepted")
	}
	lease.mountID = originalMount
	for _, field := range []*string{&lease.runnerHash, &lease.sandboxHash, &lease.imageHash} {
		original := *field
		*field = strings.Repeat("0", 64)
		if lease.Validate() == nil {
			t.Fatal("changed retained object identity accepted")
		}
		*field = original
	}
	originalImageInode := lease.imageStat.Ino
	lease.imageStat.Ino++
	if lease.Validate() == nil {
		t.Fatal("changed backing image identity accepted")
	}
	lease.imageStat.Ino = originalImageInode
	for _, test := range []struct{ name, sandbox, mount, image string }{
		{"wrong-image-inode", "runsc", "mount", "wrong-inode.squashfs"},
		{"writable-image", "runsc", "mount", "writable.squashfs"},
		{"executable-symlink", "runsc-link", "mount", "image.squashfs"},
		{"not-squashfs", "runsc", "source", "image.squashfs"},
	} {
		t.Run(test.name, func(t *testing.T) {
			unexpected, err := Acquire(context.Background(), filepath.Join(root, test.sandbox), filepath.Join(root, test.mount), filepath.Join(root, test.image))
			if unexpected != nil {
				unexpected.Close()
			}
			if err == nil {
				t.Fatal("unsafe measured input accepted")
			}
		})
	}
	output, err := exec.Command(lease.SandboxPath(), "--version").Output()
	if err != nil || len(output) == 0 {
		t.Fatal("retained sandbox executable unavailable")
	}
	bundle := filepath.Join(root, "work", "bundle")
	if err := os.Mkdir(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	privateRoot := filepath.Join(bundle, ".measured-root")
	if err := os.Mkdir(privateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	spec := map[string]any{
		"ociVersion": "1.0.2", "root": map[string]any{"path": privateRoot, "readonly": true},
		"process": map[string]any{"terminal": false, "user": map[string]any{"uid": 65532, "gid": 65532}, "args": []string{"/fixture-test", "-test.run=^TestMeasurementGuestIdentity$"}, "env": []string{"PATH=/", "PROVENANCE_MEASUREMENT_GUEST=1"}, "cwd": "/", "noNewPrivileges": true},
		"linux":   map[string]any{"namespaces": []map[string]string{{"type": "pid"}, {"type": "mount"}, {"type": "network"}, {"type": "ipc"}, {"type": "uts"}}},
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, lease.SandboxPath(), "--debug", "--debug-log="+filepath.Join(root, "work", "sandbox-debug.log"), "--root="+filepath.Join(root, "work", "runsc-state"), "--ignore-cgroups", "--rootless=true", "--network=none", "--platform=systrap", "run", "--bundle="+bundle, "measurement-fixture")
	args := append([]string{"__gvisor-measured-launch", lease.RootPath(), lease.SandboxPath(), lease.ImagePath(), lease.LoopPath(), privateRoot, lease.Snapshot().RootFS.SHA256, "embedded-executable", "--"}, cmd.Args[1:]...)
	cmd = exec.CommandContext(ctx, "/tmp/measured-runner", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// This is a synthetic fixture with no customer data or credentials.
		t.Fatalf("actual retained-root execution: %v %s", err, output)
	}
	if err := lease.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if lease.Validate() == nil {
		t.Fatal("closed lease accepted")
	}
	t.Log("actual SquashFS image/loop/mount and retained executable binding verified")
}

func TestMeasurementGuestIdentity(t *testing.T) {
	if os.Getenv("PROVENANCE_MEASUREMENT_GUEST") != "1" {
		t.Skip("guest-only synthetic fixture")
	}
	if os.Getuid() != 65532 || os.Getgid() != 65532 {
		t.Fatal("guest UID/GID changed")
	}
	time.Sleep(time.Second)
}

func TestRetainedObjectIgnoresPathReplacementButDetectsByteChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(path, []byte("original-image"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	original, err := hashObject(file, 100, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("substituted-image"), 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := hashObject(file, 100, false)
	if err != nil || actual != original {
		t.Fatal("retained descriptor followed replacement path")
	}
	if _, err := file.WriteAt([]byte("changed!"), 0); err != nil {
		t.Fatal(err)
	}
	actual, err = hashObject(file, 100, false)
	if err != nil || actual == original {
		t.Fatal("retained bytes were not remeasured")
	}
	if _, err := hashObject(file, 1, false); err == nil {
		t.Fatal("object size limit ignored")
	}
}
