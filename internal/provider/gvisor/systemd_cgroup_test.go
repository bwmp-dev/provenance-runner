package gvisor

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWrapRunCommandUsesBoundedUserScope(t *testing.T) {
	provider := &Provider{config: Config{
		CgroupDriver:      CgroupDriverSystemdUser,
		SystemdRunPath:    "/usr/bin/systemd-run",
		SystemdCgroupRoot: "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice",
		systemdLauncher:   "/opt/provenance/provenance-runner",
	}}
	invocation := command{
		Path: "/opt/provenance/runsc",
		Args: []string{"--network=none", "run", "container"},
	}
	wrapped, err := provider.wrapRunCommand(invocation, cgroupLimits{
		memoryBytes: 128 << 20,
		cpuMillis:   500,
		pids:        64,
	}, "provenance-0123456789abcdef0123456789abcdef", "/var/lib/provenance/bundle/.provenance-systemd-launched")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--user",
		"--scope",
		"--collect",
		"--quiet",
		"--unit=provenance-0123456789abcdef0123456789abcdef",
		"--slice=app.slice",
		"--property=MemoryAccounting=yes",
		"--property=CPUAccounting=yes",
		"--property=TasksAccounting=yes",
		"--property=IOAccounting=yes",
		"--property=MemoryMax=134217728",
		"--property=MemorySwapMax=0",
		"--property=CPUQuota=50.0%",
		"--property=TasksMax=81",
		"--",
		"/opt/provenance/provenance-runner",
		"__gvisor-systemd-launch",
		"--marker",
		"/var/lib/provenance/bundle/.provenance-systemd-launched",
		"--scope-root",
		"/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice",
		"--unit",
		"provenance-0123456789abcdef0123456789abcdef",
		"--",
		"/opt/provenance/runsc",
		"--network=none",
		"run",
		"container",
	}
	if wrapped.Path != "/usr/bin/systemd-run" || !reflect.DeepEqual(wrapped.Args, want) {
		t.Fatalf("wrapped command = %q %#v, want exact systemd scope %#v", wrapped.Path, wrapped.Args, want)
	}
}

func TestWrapRunCommandLeavesRunscDriverUntouched(t *testing.T) {
	provider := &Provider{config: Config{CgroupDriver: CgroupDriverRunsc}}
	original := command{Path: "runsc", Args: []string{"run", "container"}}
	wrapped, err := provider.wrapRunCommand(original, cgroupLimits{}, "container", "")
	if err != nil || !reflect.DeepEqual(wrapped, original) {
		t.Fatalf("wrapped command = %#v, %v", wrapped, err)
	}
}

func TestWrapRunCommandRejectsUnsafeScopeInputs(t *testing.T) {
	provider := &Provider{config: Config{
		CgroupDriver:      CgroupDriverSystemdUser,
		SystemdRunPath:    "/usr/bin/systemd-run",
		SystemdCgroupRoot: "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice",
		systemdLauncher:   "/opt/provenance/provenance-runner",
	}}
	valid := cgroupLimits{memoryBytes: 16 << 20, cpuMillis: 10, pids: 1}
	for _, test := range []struct {
		name      string
		limits    cgroupLimits
		container string
		marker    string
	}{
		{name: "unsafe unit name", limits: valid, container: "../../escape", marker: "/bundle/.provenance-systemd-launched"},
		{name: "invalid memory", limits: cgroupLimits{memoryBytes: 1, cpuMillis: 10, pids: 1}, container: "provenance-0123456789abcdef0123456789abcdef", marker: "/bundle/.provenance-systemd-launched"},
		{name: "invalid pids", limits: cgroupLimits{memoryBytes: 16 << 20, cpuMillis: 10}, container: "provenance-0123456789abcdef0123456789abcdef", marker: "/bundle/.provenance-systemd-launched"},
		{name: "relative marker", limits: valid, container: "provenance-0123456789abcdef0123456789abcdef", marker: "relative/.provenance-systemd-launched"},
		{name: "wrong marker basename", limits: valid, container: "provenance-0123456789abcdef0123456789abcdef", marker: "/bundle/wrong-marker"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := provider.wrapRunCommand(command{Path: "runsc"}, test.limits, test.container, test.marker); err == nil {
				t.Fatal("wrapRunCommand() error = nil")
			}
		})
	}
}

func TestSystemdDriverDisablesRunscCgroupMutation(t *testing.T) {
	provider := &Provider{config: Config{CgroupDriver: CgroupDriverSystemdUser}}
	arguments := provider.runArguments("run", "container")
	joined := strings.Join(arguments, " ")
	if !strings.Contains(joined, "--ignore-cgroups=true") {
		t.Fatalf("runsc arguments do not disable nested cgroup mutation: %#v", arguments)
	}
}

func TestSystemdDriverIdentityBindsCgroupHelper(t *testing.T) {
	provider := &Provider{config: Config{
		Platform:        "systrap",
		RootFSIdentity:  "sha256:rootfs",
		runtimeIdentity: "sha256:runsc",
		CgroupDriver:    CgroupDriverSystemdUser,
		cgroupIdentity:  "systemd-run:sha256:systemd-run/launcher:sha256:runner",
	}}
	want := "gvisor/systrap/rootfs:sha256:rootfs/runsc:sha256:runsc/cgroup:systemd-user/systemd-run:sha256:systemd-run/launcher:sha256:runner"
	if got := provider.Identity(); got != want {
		t.Fatalf("Identity() = %q, want %q", got, want)
	}
}

func TestExistingCgroupRootRejectsUntrustedPaths(t *testing.T) {
	for _, path := range []string{"", "relative", "/tmp", "/sys/fs/cgroup"} {
		if _, err := existingCgroupRoot(path); err == nil {
			t.Errorf("existingCgroupRoot(%q) error = nil", path)
		}
	}
}

func TestExistingCgroupRootValidatesSliceAndProcessContainment(t *testing.T) {
	mount := t.TempDir()
	manager := filepath.Join(mount, "user.slice", "user-1001.slice", "user@1001.service")
	appSlice := filepath.Join(manager, "app.slice")
	otherSlice := filepath.Join(manager, "other.slice")
	for _, path := range []string{appSlice, otherSlice} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	inside := func() (string, bool) {
		return "/user.slice/user-1001.slice/user@1001.service/app.slice/provenance-runner.service", true
	}
	if got, err := existingCgroupRootAt(appSlice, mount, inside); err != nil || got != appSlice {
		t.Fatalf("accepted root = %q, %v", got, err)
	}
	if _, err := existingCgroupRootAt(otherSlice, mount, inside); err == nil {
		t.Fatal("non-app.slice root accepted")
	}
	outside := func() (string, bool) {
		return "/user.slice/user-1001.slice/user@1001.service/background.slice/runner.scope", true
	}
	if _, err := existingCgroupRootAt(appSlice, mount, outside); err == nil {
		t.Fatal("root outside the runner process cgroup accepted")
	}
}
