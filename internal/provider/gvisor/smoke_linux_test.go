//go:build linux

package gvisor

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == MeasuredLauncherCommand {
		if expected := os.Getenv("PROVENANCE_MEASUREMENT_EXPECTED_PROFILE"); expected != "" {
			label, err := os.ReadFile("/proc/self/attr/current")
			fields := strings.Fields(string(label))
			if err != nil || len(fields) == 0 || fields[0] != expected {
				fmt.Fprintln(os.Stderr, "disposable guest did not enter the exact existing profile")
				os.Exit(1)
			}
			fmt.Fprintln(os.Stderr, "disposable guest entered existing profile:", expected)
		}
		os.Exit(RunMeasuredLauncher(os.Args[2:], os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == MeasuredChildCommand {
		os.Exit(RunMeasuredChild(os.Args[2:], os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == SystemdLauncherCommand {
		os.Exit(RunSystemdLauncher(os.Args[2:], os.Stderr))
	}
	os.Exit(m.Run())
}

func TestMeasuredNamespaceProbeChild(t *testing.T) {
	if os.Getenv("PROVENANCE_MEASURED_NAMESPACE_PROBE") != "1" {
		t.Skip("owned diagnostic child only")
	}
	if os.Getenv("PROVENANCE_MEASURED_NAMESPACE_MAPPED") == "1" && (os.Getuid() != 0 || os.Getgid() != 0) {
		t.Fatal("unexpected mapped identity")
	}
	fmt.Println("MEASURED_NAMESPACE_CHILD_OK")
}

func TestMeasuredNamespaceExecDiagnostic(t *testing.T) {
	if os.Getenv("PROVENANCE_MEASURED_EXEC_DIAGNOSTIC") != "1" {
		t.Skip("owned disposable diagnostic only")
	}
	if os.Getuid() == 0 {
		t.Fatal("diagnostic requires nonroot owned user")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mapped := range []bool{false, true} {
		for _, fd := range []bool{false, true} {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			file, err := os.Open("/proc/self/exe")
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			executable := path
			if fd {
				executable = "/proc/self/fd/3"
			}
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestMeasuredNamespaceProbeChild$", "-test.count=1", "-test.v")
			cmd.Env = append(os.Environ(), "PROVENANCE_MEASURED_NAMESPACE_PROBE=1", fmt.Sprintf("PROVENANCE_MEASURED_NAMESPACE_MAPPED=%d", map[bool]int{false: 0, true: 1}[mapped]))
			cmd.ExtraFiles = []*os.File{file}
			if mapped {
				cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false, Pdeathsig: syscall.SIGKILL}
			}
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			startErr := cmd.Start()
			started := startErr == nil
			pid := 0
			if started {
				pid = cmd.Process.Pid
				err = cmd.Wait()
			} else {
				err = startErr
			}
			category := "none"
			if err != nil {
				category = namespaceFailureCategory(err)
			}
			result := map[string]any{"version": 1, "mapped": mapped, "retainedFD": fd, "started": started, "pid": pid, "uid": os.Getuid(), "errorCategory": category, "childConfirmed": err == nil && strings.Contains(output.String(), "MEASURED_NAMESPACE_CHILD_OK")}
			encoded, _ := json.Marshal(result)
			t.Log("MEASURED_EXEC_PROBE=" + string(encoded))
			file.Close()
			cancel()
		}
	}
}

func TestRunscSmoke(t *testing.T) {
	if os.Getenv("PROVENANCE_RUNSC_SMOKE") != "1" {
		t.Skip("set PROVENANCE_RUNSC_SMOKE=1 to opt in to the real sandbox smoke test")
	}
	runscPath := os.Getenv("PROVENANCE_RUNSC_PATH")
	if runscPath == "" {
		runscPath = "runsc"
	}
	resolvedRunsc, err := exec.LookPath(runscPath)
	if err != nil {
		t.Fatalf("PROVENANCE_RUNSC_SMOKE=1 requires runsc (%v)", err)
	}
	rootFS := os.Getenv("PROVENANCE_RUNSC_ROOTFS")
	if rootFS == "" {
		t.Fatal("PROVENANCE_RUNSC_SMOKE=1 requires PROVENANCE_RUNSC_ROOTFS containing /bin/sh")
	}
	identity, closeIdentity, err := smokeRootIdentity(rootFS, resolvedRunsc, os.Getenv("PROVENANCE_MEASURED_ROOTFS_IMAGE"), os.Getenv("PROVENANCE_MEASURED_LOOP_DEVICE"))
	if err != nil {
		t.Fatalf("capture measured root identity before smoke: %v", err)
	}
	defer closeIdentity()
	rootFSIdentityBefore, err := identity()
	if err != nil {
		t.Fatalf("capture root filesystem identity before smoke: %v", err)
	}
	defer func() {
		rootFSIdentityAfter, err := identity()
		if err != nil {
			t.Errorf("capture root filesystem identity after smoke: %v", err)
			return
		}
		if rootFSIdentityAfter != rootFSIdentityBefore {
			t.Errorf("root filesystem identity changed across execution, cancellation, restart, or FIFO cleanup: before=%s after=%s", rootFSIdentityBefore, rootFSIdentityAfter)
		}
	}()

	temporaryRoot := t.TempDir()
	inputsRoot := filepath.Join(temporaryRoot, "inputs")
	for _, jobID := range []string{"smoke", "smoke-events", "smoke-cancel", "smoke-restart"} {
		if err := os.MkdirAll(filepath.Join(inputsRoot, jobID), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stateRoot := filepath.Join(temporaryRoot, "state")
	bundleRoot := filepath.Join(temporaryRoot, "bundles")
	providerConfig := Config{
		RunscPath:            resolvedRunsc,
		CgroupDriver:         os.Getenv("PROVENANCE_GVISOR_CGROUP_DRIVER"),
		SystemdRunPath:       os.Getenv("PROVENANCE_SYSTEMD_RUN_PATH"),
		SystemdCgroupRoot:    os.Getenv("PROVENANCE_SYSTEMD_CGROUP_ROOT"),
		RootFS:               rootFS,
		RootFSImagePath:      os.Getenv("PROVENANCE_MEASURED_ROOTFS_IMAGE"),
		RootFSLoopDevicePath: os.Getenv("PROVENANCE_MEASURED_LOOP_DEVICE"),
		MeasuredRuntimeMode:  os.Getenv("PROVENANCE_MEASURED_RUNTIME_MODE"),
		RootFSIdentity:       "sha256:" + rootFSIdentityBefore,
		StateRoot:            stateRoot,
		BundleRoot:           bundleRoot,
		InputsRoot:           inputsRoot,
		Platform:             "systrap",
	}
	provider, err := New(providerConfig)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := provider.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if provider.config.RootFSImagePath != "" {
		t.Run("cancelled cleanup retains exact objects for retry", func(t *testing.T) {
			prepared := prepareSmokeEnvironment(t, provider, "smoke", configuration{Command: "/bin/true", Network: "none", MemoryBytes: 128 << 20, CPUMillis: 500, PIDs: 64, DiskBytes: 8 << 20})
			defer cleanupSmokeEnvironment(t, prepared)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if !errors.Is(prepared.Cleanup(ctx), context.Canceled) {
				t.Fatal("cancelled cleanup unexpectedly succeeded")
			}
			if prepared.measurement == nil || prepared.measurement.Validate() != nil {
				t.Fatal("failed cleanup lost retained runtime identity")
			}
			cleanupSmokeEnvironment(t, prepared)
			if prepared.measurement.Validate() == nil {
				t.Fatal("successful cleanup retained open identity lease")
			}
		})
	}
	if provider.config.CgroupDriver == CgroupDriverSystemdUser {
		t.Run("systemd user scope applies exact limits", func(t *testing.T) {
			config := configuration{
				Command:     "/bin/sh",
				Arguments:   []string{"-c", `trap '' TERM; while :; do sleep 1; done`},
				Network:     "none",
				MemoryBytes: 128 << 20,
				CPUMillis:   500,
				PIDs:        64,
				DiskBytes:   8 << 20,
			}
			prepared := prepareSmokeEnvironment(t, provider, "smoke", config)
			defer cleanupSmokeEnvironment(t, prepared)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := prepared.Execute(ctx)
				result <- err
			}()
			scope := systemdCgroupPath(provider.config.SystemdCgroupRoot, prepared.containerID)
			waitForExactSystemdLimits(t, scope, map[string]string{
				"memory.max":      "134217728",
				"memory.swap.max": "0",
				"cpu.max":         "50000 100000",
				"pids.max":        "81",
			}, result)
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Execute() after cancellation = %v", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("systemd-scoped smoke did not stop after cancellation")
			}
			cleanupSmokeEnvironment(t, prepared)
			assertNoSandboxResidue(t, provider, prepared.containerID)
			waitForScopeRemoval(t, scope)
		})
	}

	t.Run("sealed secret files and redaction", func(t *testing.T) {
		secret := []byte("synthetic-sealed-smoke")
		files, err := testsecrets.New([]testsecrets.Input{{Name: "token", Value: secret}})
		if err != nil {
			t.Fatal("create synthetic memory files failed")
		}
		defer files.Close()
		mounts, err := files.Mounts()
		if err != nil {
			t.Fatal(err)
		}
		env, err := provider.ResolveWorkload(context.Background(), execution.Request{JobID: "smoke", Limits: execution.Limits{MaxOutputBytes: 65536}}, execution.IsolatedWorkload{
			Command: "/bin/sh", Arguments: []string{"-c", `test "$(id -u)" = 65532 && test "$(wc -c < /run/provenance/test-secrets/token)" = 22 && ! (printf x > /run/provenance/test-secrets/token) 2>/dev/null && ! touch /run/escape 2>/dev/null && cat /run/provenance/test-secrets/token && echo && echo secret-file-smoke-ok`},
			InputsPath: filepath.Join(inputsRoot, "smoke"), Network: "none", MemoryBytes: 128 << 20, CPUMillis: 500, PIDs: 64, DiskBytes: 8 << 20, TestSecretFiles: files,
		})
		if err != nil {
			t.Fatal("resolve secret sandbox failed:", err)
		}
		owned, err := env.Prepare(context.Background())
		if err != nil {
			t.Fatal("prepare secret sandbox failed:", err)
		}
		prepared := owned.(*preparedEnvironment)
		defer cleanupSmokeEnvironment(t, prepared)
		live := &secretSmokeObserver{}
		prepared.AttachObserver(live)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		outcome, err := prepared.Execute(ctx)
		if err != nil || outcome.Failure != nil {
			t.Fatal("synthetic secret sandbox failed:", err)
		}
		output, err := prepared.Collect(ctx)
		if err != nil || !strings.Contains(output.Stdout, "secret-file-smoke-ok") || strings.Contains(output.Stdout, string(secret)) || strings.Contains(output.Stderr, string(secret)) {
			t.Fatal("secret read/redaction assertion failed")
		}
		if !strings.Contains(live.text(), "secret-file-smoke-ok") || strings.Contains(live.text(), string(secret)) {
			t.Fatal("live secret redaction failed")
		}
		if output.CompleteLog == nil || output.CompleteLog.Archive == nil {
			t.Fatal("complete redacted log missing")
		}
		defer output.CompleteLog.Archive.Close()
		archive, err := gzip.NewReader(io.NewSectionReader(output.CompleteLog.Archive, 0, output.CompleteLog.CompressedBytes))
		if err != nil {
			t.Fatal("complete log framing failed")
		}
		complete, err := io.ReadAll(io.LimitReader(archive, 65537))
		archive.Close()
		if err != nil || len(complete) > 65536 || !bytes.Contains(complete, []byte("secret-file-smoke-ok")) || bytes.Contains(complete, secret) {
			t.Fatal("stored secret redaction failed")
		}
		cancelled, stop := context.WithCancel(context.Background())
		stop()
		if !errors.Is(prepared.Cleanup(cancelled), context.Canceled) {
			t.Fatal("cancelled cleanup unexpectedly completed")
		}
		if _, err := files.Mounts(); err != nil {
			t.Fatal("failed cleanup prematurely closed memory handles")
		}
		cleanupSmokeEnvironment(t, prepared)
		if _, err := files.Mounts(); err == nil {
			t.Fatal("successful cleanup retained memory handles")
		}
		for _, mount := range mounts {
			if _, err := os.Stat(mount.Source); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("secret descriptor survived cleanup")
			}
		}
		assertNoSandboxResidue(t, provider, prepared.containerID)
	})

	t.Run("contained execution and cleanup", func(t *testing.T) {
		config := configuration{
			Command:     "/bin/sh",
			Arguments:   []string{"-c", `test "$(id -u)" = 65532 && test "$TMPDIR" = /tmp && touch /workspace/ok && touch /tmp/ok && ! touch /provenance-root-write-test && test ! -S /run/docker.sock && test "$(tail -n +2 /proc/net/route | wc -l)" = 0 && ! nc -z -w 1 10.0.0.1 80 && ! nc -z -w 1 169.254.169.254 80 && sleep 1 && echo gvisor-smoke-ok && echo gvisor-network-none-ok`},
			Network:     "none",
			MemoryBytes: 128 << 20,
			CPUMillis:   500,
			PIDs:        64,
			DiskBytes:   8 << 20,
		}
		prepared := prepareSmokeEnvironment(t, provider, "smoke", config)
		defer cleanupSmokeEnvironment(t, prepared)
		containerID := prepared.containerID
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		outcome, executeErr := prepared.Execute(ctx)
		output, collectErr := prepared.Collect(ctx)
		if executeErr != nil {
			t.Fatalf("Execute() error = %v; stdout=%q stderr=%q; Collect() error = %v", executeErr, output.Stdout, output.Stderr, collectErr)
		}
		if collectErr != nil {
			t.Fatalf("Collect() error = %v", collectErr)
		}
		if outcome.Failure != nil {
			t.Fatalf("Execute() failure = %#v; stdout=%q stderr=%q", outcome.Failure, output.Stdout, output.Stderr)
		}
		if !strings.Contains(output.Stdout, "gvisor-smoke-ok") {
			t.Fatalf("sandbox output did not confirm containment checks; stdout=%q stderr=%q", output.Stdout, output.Stderr)
		}
		if !strings.Contains(output.Stdout, "gvisor-network-none-ok") {
			t.Fatalf("sandbox output did not confirm failed private and metadata probes; stdout=%q stderr=%q", output.Stdout, output.Stderr)
		}
		if output.ResourceUsage == nil || output.ResourceUsage.CPUTime <= 0 || output.ResourceUsage.PeakMemoryBytes == 0 || output.ResourceUsage.NetworkReceiveBytes != 0 || output.ResourceUsage.NetworkTransmitBytes != 0 {
			t.Fatalf("sandbox measured usage = %#v", output.ResourceUsage)
		}
		if providerConfig.RootFSImagePath != "" && (output.MeasuredRuntime == nil || !output.MeasuredRuntime.Valid()) {
			t.Fatal("actual measured execution omitted runtime identity")
		}
		if output.MeasuredRuntime != nil {
			original := *output.MeasuredRuntime
			output.MeasuredRuntime.RootFS.SHA256 = strings.Repeat("0", 64)
			again, err := prepared.Collect(ctx)
			if err != nil || again.MeasuredRuntime == nil || *again.MeasuredRuntime != original {
				t.Fatal("collected runtime aliases caller mutation")
			}
			output.MeasuredRuntime = again.MeasuredRuntime
		}
		if providerConfig.RootFSImagePath == "" && output.MeasuredRuntime != nil {
			t.Fatal("legacy root reported measured runtime")
		}
		cleanupSmokeEnvironment(t, prepared)
		assertNoSandboxResidue(t, provider, containerID)
	})

	t.Run("live bounded event FIFO survives nonzero exit", func(t *testing.T) {
		environment, err := provider.ResolveWorkload(context.Background(), execution.Request{
			JobID:  "smoke-events",
			Limits: execution.Limits{MaxOutputBytes: 64 << 10},
		}, execution.IsolatedWorkload{
			Command:     "/bin/sh",
			Arguments:   []string{"-c", `printf '{"state":"ready"}\n' > /tmp/provenance-probe-events.ndjson; exit 2`},
			InputsPath:  filepath.Join(inputsRoot, "smoke-events"),
			Network:     "none",
			MemoryBytes: 128 << 20,
			CPUMillis:   500,
			PIDs:        64,
			DiskBytes:   8 << 20,
			StructuredEventFile: &execution.StructuredEventFile{
				Destination:  "/tmp/provenance-probe-events.ndjson",
				Kind:         "smoke",
				MaximumBytes: 1024,
			},
		})
		if err != nil {
			t.Fatalf("ResolveWorkload() error = %v", err)
		}
		preparedValue, err := environment.Prepare(context.Background())
		if err != nil {
			t.Fatalf("Prepare() error = %v", err)
		}
		prepared := preparedValue.(*preparedEnvironment)
		defer cleanupSmokeEnvironment(t, prepared)
		containerID := prepared.containerID
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		outcome, executeErr := prepared.Execute(ctx)
		output, collectErr := prepared.Collect(ctx)
		if executeErr != nil {
			t.Fatalf("Execute() error = %v; stdout=%q stderr=%q; Collect() error=%v", executeErr, output.Stdout, output.Stderr, collectErr)
		}
		if collectErr != nil {
			t.Fatalf("Collect() error = %v", collectErr)
		}
		if outcome.Failure == nil || outcome.Failure.Code != "gvisor_process_exit_nonzero" {
			t.Fatalf("Execute() outcome = %#v", outcome)
		}
		if len(output.StructuredEvents) != 1 || output.StructuredEvents[0].Kind != "smoke" || string(output.StructuredEvents[0].Payload) != `{"state":"ready"}` {
			t.Fatalf("structured events = %#v; channel error=%q", output.StructuredEvents, output.StructuredEventError)
		}
		if output.EvidenceUsage.EventChannelMaximumBytes != 1024 || output.EvidenceUsage.EventChannelBufferedBytes != 18 || output.EvidenceUsage.EventChannelResourceBytes != 0 || output.EvidenceUsage.EventChannelOverflowed || !output.EvidenceUsage.EventChannelRemoved {
			t.Fatalf("event channel usage = %#v", output.EvidenceUsage)
		}
		cleanupSmokeEnvironment(t, prepared)
		assertNoSandboxResidue(t, provider, containerID)
	})

	t.Run("real cancellation cleanup", func(t *testing.T) {
		config := configuration{
			Command:     "/bin/sh",
			Arguments:   []string{"-c", `trap '' TERM; while :; do :; done`},
			Network:     "none",
			MemoryBytes: 128 << 20,
			CPUMillis:   100,
			PIDs:        64,
			DiskBytes:   8 << 20,
		}
		prepared := prepareSmokeEnvironment(t, provider, "smoke-cancel", config)
		containerID := prepared.containerID
		defer cleanupSmokeEnvironment(t, prepared)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, executeErr := prepared.Execute(ctx)
		output, collectErr := prepared.Collect(context.Background())
		if !errors.Is(executeErr, context.DeadlineExceeded) {
			t.Fatalf("Execute() error = %v, want deadline exceeded; stdout=%q stderr=%q; Collect() error=%v", executeErr, output.Stdout, output.Stderr, collectErr)
		}
		if collectErr != nil {
			t.Fatalf("Collect() after cancellation error = %v", collectErr)
		}
		cleanupSmokeEnvironment(t, prepared)
		assertNoSandboxResidue(t, provider, containerID)
	})

	t.Run("real restart reconciliation", func(t *testing.T) {
		config := configuration{
			Command:     "/bin/sh",
			Arguments:   []string{"-c", `trap '' TERM; while :; do sleep 1; done`},
			Network:     "none",
			MemoryBytes: 128 << 20,
			CPUMillis:   100,
			PIDs:        64,
			DiskBytes:   8 << 20,
		}
		prepared := prepareSmokeEnvironment(t, provider, "smoke-restart", config)
		if err := prepared.markRunAttempted(); err != nil {
			t.Fatalf("markRunAttempted() error = %v", err)
		}
		containerID := prepared.containerID
		var runOutput bytes.Buffer
		invocation, err := prepared.provider.wrapRunCommand(prepared.executionCommand(nil, nil), prepared.cgroupLimits, containerID, filepath.Join(prepared.bundle, systemdLaunchMarker))
		if err != nil {
			t.Fatalf("configure abandoned runsc command: %v", err)
		}
		run := exec.Command(invocation.Path, invocation.Args...)
		run.Stdout = &runOutput
		run.Stderr = &runOutput
		if err := run.Start(); err != nil {
			t.Fatalf("start abandoned runsc container: %v", err)
		}
		runDone := make(chan error, 1)
		go func() { runDone <- run.Wait() }()
		cleanupNeeded := true
		defer func() {
			if !cleanupNeeded {
				return
			}
			cleanupContext, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
			defer cancel()
			_ = run.Process.Kill()
			_ = provider.runner.Run(cleanupContext, command{
				Path: provider.config.RunscPath,
				Args: provider.runArguments("kill", "--all", containerID, "KILL"),
			}).Err
			_ = provider.runner.Run(cleanupContext, command{
				Path: provider.config.RunscPath,
				Args: provider.runArguments("delete", "--force", containerID),
			}).Err
			_ = removeOwnedBundle(provider.config.BundleRoot, prepared.bundle)
		}()
		waitForRunscState(t, provider, containerID, runDone, &runOutput)

		restarted, err := New(providerConfig)
		if err != nil {
			t.Fatalf("restart New() error = %v", err)
		}
		if err := restarted.Reconcile(context.Background()); err != nil {
			t.Fatalf("restart Reconcile() error = %v", err)
		}
		waitForProcessExit(t, run, runDone)
		assertNoSandboxResidue(t, restarted, containerID)
		cleanupNeeded = false
	})
}

type secretSmokeObserver struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (o *secretSmokeObserver) ObserveLog(entry execution.LiveLogEntry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.data.Write(entry.Data)
}
func (*secretSmokeObserver) ObserveUsage(execution.ResourceUsage) {}
func (o *secretSmokeObserver) text() string                       { o.mu.Lock(); defer o.mu.Unlock(); return o.data.String() }

func smokeRootIdentity(root, sandbox, image, loop string) (func() (string, error), func() error, error) {
	if image == "" {
		return func() (string, error) { return normalizedRootFSTreeSHA256(root) }, func() error { return nil }, nil
	}
	// Preserve root-owned private files; the measured contract is the complete
	// immutable image and its retained mount/loop binding, not a nonroot tar.
	measurement, err := runtimeidentity.Acquire(context.Background(), sandbox, root, image, loop)
	if err != nil {
		return nil, nil, err
	}
	return func() (string, error) {
		if err := measurement.Validate(); err != nil {
			return "", err
		}
		return measurement.Snapshot().RootFS.SHA256, nil
	}, measurement.Close, nil
}

func TestMeasuredPreflightWithProtectedImageFiles(t *testing.T) {
	root := os.Getenv("PROVENANCE_MEASUREMENT_FIXTURE_ROOT")
	if root == "" {
		t.Skip("disposable privileged fixture required")
	}
	expectedUID := 1000
	if raw := os.Getenv("PROVENANCE_MEASUREMENT_FIXTURE_UID"); raw != "" {
		var err error
		expectedUID, err = strconv.Atoi(raw)
		if err != nil || (expectedUID != 1000 && (expectedUID < 60000 || expectedUID > 63999)) {
			t.Fatal("unexpected fixture UID")
		}
	}
	if root != "/tmp/provenance-runtime-fixture" || os.Getuid() != expectedUID {
		t.Fatal("unexpected fixture")
	}
	if _, err := os.ReadFile(filepath.Join(root, "mount", "private-root-file")); !errors.Is(err, os.ErrPermission) {
		t.Fatal("protected file was weakened")
	}
	legacy, closeLegacy, err := smokeRootIdentity(filepath.Join(root, "mount"), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer closeLegacy()
	if _, err := legacy(); err == nil {
		t.Fatal("expected legacy tar permission failure")
	}
	identity, closeIdentity, err := smokeRootIdentity(filepath.Join(root, "mount"), filepath.Join(root, "runsc"), filepath.Join(root, "image.squashfs"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer closeIdentity()
	before, err := identity()
	if err != nil {
		t.Fatal(err)
	}
	after, err := identity()
	if err != nil || before != after {
		t.Fatal("measured identity drift")
	}
	if err := closeIdentity(); err != nil {
		t.Fatal(err)
	}
	if _, err := identity(); err == nil {
		t.Fatal("closed identity accepted")
	}
}

func normalizedRootFSTreeSHA256(rootFS string) (string, error) {
	digest := sha256.New()
	var stderr bytes.Buffer
	command := exec.Command("tar", "--sort=name", "--format=gnu", "--mtime=@0", "--owner=0", "--group=0", "--numeric-owner", "-cf", "-", "-C", rootFS, ".")
	command.Stdout = digest
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("hash normalized root filesystem tree: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return fmt.Sprintf("%x", digest.Sum(nil)), nil
}

func waitForExactSystemdLimits(t *testing.T, scope string, expected map[string]string, execution <-chan error) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	last := "unobserved"
	for time.Now().Before(deadline) {
		select {
		case <-execution:
			t.Fatal("systemd limit observation: execution ended before limits were verified")
		default:
		}
		last = systemdLimitObservation(scope, expected)
		if last == "matched" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("systemd scope did not expose exact resource limits: %s", last)
}

func systemdLimitObservation(scope string, expected map[string]string) string {
	for name, want := range expected {
		data, err := os.ReadFile(filepath.Join(scope, name))
		if errors.Is(err, os.ErrNotExist) {
			return "scope_or_limit_absent"
		}
		if err != nil {
			return "limit_unreadable"
		}
		if strings.TrimSpace(string(data)) != want {
			return "limit_mismatch"
		}
	}
	return "matched"
}

func TestSystemdLimitObservationAttribution(t *testing.T) {
	scope := t.TempDir()
	expected := map[string]string{"pids.max": "81"}
	if systemdLimitObservation(scope, expected) != "scope_or_limit_absent" {
		t.Fatal("absent limit misclassified")
	}
	path := filepath.Join(scope, "pids.max")
	if err := os.WriteFile(path, []byte("80\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if systemdLimitObservation(scope, expected) != "limit_mismatch" {
		t.Fatal("wrong limit misclassified")
	}
	if err := os.WriteFile(path, []byte("81\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if systemdLimitObservation(scope, expected) != "matched" {
		t.Fatal("exact limit rejected")
	}
}

func waitForScopeRemoval(t *testing.T, scope string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(scope); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("systemd scope %q remained after collection", scope)
}

func prepareSmokeEnvironment(t *testing.T, provider *Provider, jobID string, config configuration) *preparedEnvironment {
	t.Helper()
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := provider.Resolve(context.Background(), execution.Request{
		JobID:       jobID,
		Environment: content,
		Limits:      execution.Limits{MaxOutputBytes: 64 << 10},
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	prepared, err := environment.Prepare(context.Background())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	resolved, ok := prepared.(*preparedEnvironment)
	if !ok {
		t.Fatalf("prepared environment type = %T", prepared)
	}
	return resolved
}

func cleanupSmokeEnvironment(t *testing.T, prepared *preparedEnvironment) {
	t.Helper()
	cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cleanupCancel()
	if err := prepared.Cleanup(cleanupContext); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
}

func waitForRunscState(t *testing.T, provider *Provider, containerID string, runDone <-chan error, output *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-runDone:
			t.Fatalf("abandoned runsc process exited before state was queryable: %v; output=%q", err, output.String())
		default:
		}
		result := provider.runner.Run(context.Background(), command{
			Path: provider.config.RunscPath,
			Args: provider.runArguments("state", containerID),
		})
		if result.Err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("runsc container %s did not reach a queryable state", containerID)
}

func waitForProcessExit(t *testing.T, process *exec.Cmd, done <-chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = process.Process.Kill()
		t.Fatal("abandoned runsc process did not exit after reconciliation")
	}
}

func assertNoSandboxResidue(t *testing.T, provider *Provider, containerIDs ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var residue []string
	for {
		residue = sandboxResidue(provider, containerIDs...)
		if len(residue) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox residue after cleanup:\n%s", strings.Join(residue, "\n"))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func sandboxResidue(provider *Provider, containerIDs ...string) []string {
	var residue []string
	for _, root := range []string{provider.config.StateRoot, provider.config.BundleRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			residue = append(residue, fmt.Sprintf("read %s: %v", root, err))
			continue
		}
		for _, entry := range entries {
			residue = append(residue, filepath.Join(root, entry.Name()))
		}
	}

	cgroupParent := os.Getenv("PROVENANCE_CGROUP_PARENT")
	if cgroupParent != "" {
		_ = filepath.WalkDir(cgroupParent, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() && validContainerID(entry.Name()) {
				residue = append(residue, "job cgroup "+path)
			}
			return nil
		})
	}

	procEntries, _ := os.ReadDir("/proc")
	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		processRoot := filepath.Join("/proc", entry.Name())
		commandLine, err := os.ReadFile(filepath.Join(processRoot, "cmdline"))
		if err == nil && containsSandboxIdentity(commandLine, provider, containerIDs) {
			networkNamespace, _ := os.Readlink(filepath.Join(processRoot, "ns/net"))
			residue = append(residue, fmt.Sprintf("process %s (%q, net=%s)", entry.Name(), bytes.ReplaceAll(commandLine, []byte{0}, []byte{' '}), networkNamespace))
		}
		mountInfo, err := os.ReadFile(filepath.Join(processRoot, "mountinfo"))
		if err == nil && containsSandboxIdentity(mountInfo, provider, containerIDs) {
			residue = append(residue, fmt.Sprintf("mount namespace held by process %s", entry.Name()))
		}
	}
	return residue
}

func containsSandboxIdentity(content []byte, provider *Provider, containerIDs []string) bool {
	for _, identity := range append([]string{provider.config.StateRoot, provider.config.BundleRoot}, containerIDs...) {
		if identity != "" && bytes.Contains(content, []byte(identity)) {
			return true
		}
	}
	return false
}
