//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == SystemdLauncherCommand {
		os.Exit(RunSystemdLauncher(os.Args[2:], os.Stderr))
	}
	os.Exit(m.Run())
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
		RunscPath:         resolvedRunsc,
		CgroupDriver:      os.Getenv("PROVENANCE_GVISOR_CGROUP_DRIVER"),
		SystemdRunPath:    os.Getenv("PROVENANCE_SYSTEMD_RUN_PATH"),
		SystemdCgroupRoot: os.Getenv("PROVENANCE_SYSTEMD_CGROUP_ROOT"),
		RootFS:            rootFS,
		RootFSIdentity:    "smoke-rootfs",
		StateRoot:         stateRoot,
		BundleRoot:        bundleRoot,
		InputsRoot:        inputsRoot,
		Platform:          "systrap",
	}
	provider, err := New(providerConfig)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := provider.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

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
		invocation, err := provider.wrapRunCommand(command{
			Path: provider.config.RunscPath,
			Args: provider.runArguments("run", "--bundle="+prepared.bundle, containerID),
		}, prepared.cgroupLimits, containerID, filepath.Join(prepared.bundle, systemdLaunchMarker))
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
