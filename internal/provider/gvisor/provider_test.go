package gvisor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
)

func TestPrepareWritesContainedOCIConfiguration(t *testing.T) {
	provider, runner, roots := testProvider(t)
	environment := resolveEnvironment(t, provider, validConfiguration(), 4096)
	preparedValue, err := environment.Prepare(context.Background())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	prepared := preparedValue.(*preparedEnvironment)
	t.Cleanup(func() { _ = prepared.Cleanup(context.Background()) })

	content, err := os.ReadFile(filepath.Join(prepared.bundle, "config.json"))
	if err != nil {
		t.Fatalf("ReadFile(config.json) error = %v", err)
	}
	var spec ociSpec
	if err := json.Unmarshal(content, &spec); err != nil {
		t.Fatalf("Unmarshal(config.json) error = %v", err)
	}

	if spec.OCIVersion != "1.1.0" {
		t.Errorf("OCIVersion = %q", spec.OCIVersion)
	}
	if spec.Root.Path != roots.rootFS || !spec.Root.Readonly {
		t.Errorf("Root = %#v, want path %q and readonly", spec.Root, roots.rootFS)
	}
	if spec.Process.User.UID != containerUID || spec.Process.User.GID != containerGID || len(spec.Process.User.AdditionalGids) != 0 {
		t.Errorf("Process.User = %#v", spec.Process.User)
	}
	if !spec.Process.NoNewPrivileges {
		t.Error("NoNewPrivileges = false")
	}
	capabilitySets := [][]string{
		spec.Process.Capabilities.Bounding,
		spec.Process.Capabilities.Effective,
		spec.Process.Capabilities.Inheritable,
		spec.Process.Capabilities.Permitted,
		spec.Process.Capabilities.Ambient,
	}
	for index, capabilities := range capabilitySets {
		if capabilities == nil || len(capabilities) != 0 {
			t.Errorf("capability set %d = %#v, want explicit empty array", index, capabilities)
		}
	}
	if !reflect.DeepEqual(spec.Process.Args, []string{"/usr/bin/java", "-jar", "/inputs/server.jar"}) {
		t.Errorf("Process.Args = %#v", spec.Process.Args)
	}
	if spec.Process.Cwd != "/workspace" {
		t.Errorf("Process.Cwd = %q", spec.Process.Cwd)
	}
	if !reflect.DeepEqual(spec.Process.Env, []string{"A=first", "HOME=/workspace", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TMPDIR=/tmp", "Z=last"}) {
		t.Errorf("Process.Env = %#v", spec.Process.Env)
	}

	namespaces := make([]string, 0, len(spec.Linux.Namespaces))
	for _, namespace := range spec.Linux.Namespaces {
		namespaces = append(namespaces, namespace.Type)
	}
	if !reflect.DeepEqual(namespaces, []string{"pid", "network", "mount", "ipc", "uts", "cgroup"}) {
		t.Errorf("Namespaces = %#v", namespaces)
	}
	if spec.Linux.Resources.Memory.Limit != 256<<20 || spec.Linux.Resources.Memory.Swap != 256<<20 {
		t.Errorf("Memory = %#v", spec.Linux.Resources.Memory)
	}
	if spec.Linux.Resources.CPU.Quota != 150_000 || spec.Linux.Resources.CPU.Period != 100_000 {
		t.Errorf("CPU = %#v", spec.Linux.Resources.CPU)
	}
	if spec.Linux.Resources.PIDs.Limit != 64 {
		t.Errorf("PIDs = %#v", spec.Linux.Resources.PIDs)
	}
	wantDevices := []ociDevice{
		{Path: "/dev/null", Type: "c", Major: 1, Minor: 3, FileMode: 0o666},
		{Path: "/dev/zero", Type: "c", Major: 1, Minor: 5, FileMode: 0o666},
		{Path: "/dev/full", Type: "c", Major: 1, Minor: 7, FileMode: 0o666},
		{Path: "/dev/random", Type: "c", Major: 1, Minor: 8, FileMode: 0o666},
		{Path: "/dev/urandom", Type: "c", Major: 1, Minor: 9, FileMode: 0o666},
		{Path: "/dev/tty", Type: "c", Major: 5, Minor: 0, FileMode: 0o666},
	}
	if !reflect.DeepEqual(spec.Linux.Devices, wantDevices) {
		t.Errorf("Linux.Devices = %#v", spec.Linux.Devices)
	}
	if len(spec.Linux.Resources.Devices) != len(spec.Linux.Devices)+1 || spec.Linux.Resources.Devices[0] != (ociDeviceCgroup{Allow: false, Access: "rwm"}) {
		t.Errorf("device cgroup rules = %#v", spec.Linux.Resources.Devices)
	}
	for index, device := range spec.Linux.Devices {
		rule := spec.Linux.Resources.Devices[index+1]
		if !rule.Allow || rule.Type != "c" || rule.Major == nil || *rule.Major != device.Major || rule.Minor == nil || *rule.Minor != device.Minor || rule.Access != "rwm" {
			t.Errorf("device rule %d = %#v for device %#v", index, rule, device)
		}
		if device.FileMode != 0o666 || device.UID != 0 || device.GID != 0 {
			t.Errorf("device ownership/mode = %#v", device)
		}
	}
	if spec.Linux.CgroupsPath != "provenance/"+prepared.containerID {
		t.Errorf("CgroupsPath = %q", spec.Linux.CgroupsPath)
	}

	workspace := findMount(t, spec.Mounts, "/workspace")
	if workspace.Type != "tmpfs" || !containsAll(workspace.Options, "nosuid", "nodev", "mode=0700", "uid=65532", "gid=65532", "size=16777216") {
		t.Errorf("workspace mount = %#v", workspace)
	}
	temporary := findMount(t, spec.Mounts, "/tmp")
	if temporary.Type != "tmpfs" || !containsAll(temporary.Options, "nosuid", "nodev", "mode=0700", "uid=65532", "gid=65532", "size=16777216") {
		t.Errorf("temporary mount = %#v", temporary)
	}
	inputs := findMount(t, spec.Mounts, "/inputs")
	if inputs.Source != filepath.Join(roots.inputs, "job-1") || !reflect.DeepEqual(inputs.Options, []string{"rbind", "ro", "nosuid", "nodev", "noexec"}) {
		t.Errorf("inputs mount = %#v", inputs)
	}
	for _, mount := range spec.Mounts {
		if strings.Contains(strings.ToLower(mount.Source), "docker.sock") || strings.Contains(strings.ToLower(mount.Destination), "docker.sock") {
			t.Fatalf("Docker socket exposed by mount %#v", mount)
		}
		if strings.HasPrefix(mount.Destination, "/dev") && mount.Type == "bind" {
			t.Fatalf("host device exposed by bind mount %#v", mount)
		}
	}
	for _, limit := range spec.Process.Rlimits {
		if limit.Type == "RLIMIT_FSIZE" && (limit.Hard != 32<<20 || limit.Soft != 32<<20) {
			t.Errorf("RLIMIT_FSIZE = %#v", limit)
		}
	}
	if _, err := os.Stat(filepath.Join(prepared.bundle, metadataName)); err != nil {
		t.Errorf("metadata file error = %v", err)
	}
	metadata, err := readMetadata(filepath.Join(prepared.bundle, metadataName))
	if err != nil {
		t.Fatalf("readMetadata() error = %v", err)
	}
	if metadata.Phase != metadataPhasePrepared {
		t.Errorf("metadata phase = %q", metadata.Phase)
	}
	if _, err := os.Stat(filepath.Join(prepared.bundle, attemptName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("run-attempt marker exists before Execute: %v", err)
	}
	if len(runner.commands()) != 0 {
		t.Errorf("runtime invoked during preparation: %#v", runner.commands())
	}
}

func TestResolveWorkloadMountsOnlyTrustedReadOnlyInputs(t *testing.T) {
	provider, _, roots := testProvider(t)
	jobRoot := filepath.Join(roots.inputs, "job-1")
	runtimeRoot := filepath.Join(jobRoot, "runtime")
	if err := os.Mkdir(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	workload := execution.IsolatedWorkload{
		Command:        "/bin/sh",
		Arguments:      []string{"-c", "true"},
		InputsPath:     jobRoot,
		ReadOnlyMounts: []execution.ReadOnlyMount{{Source: runtimeRoot, Destination: "/runtime", Executable: true}},
		Network:        "none",
		MemoryBytes:    256 << 20,
		CPUMillis:      1000,
		PIDs:           32,
		DiskBytes:      64 << 20,
	}
	environment, err := provider.ResolveWorkload(context.Background(), execution.Request{
		JobID: "job-1", Limits: execution.Limits{MaxOutputBytes: 1024},
	}, workload)
	if err != nil {
		t.Fatalf("ResolveWorkload() error = %v", err)
	}
	preparedValue, err := environment.Prepare(context.Background())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	prepared := preparedValue.(*preparedEnvironment)
	t.Cleanup(func() { _ = prepared.Cleanup(context.Background()) })
	content, err := os.ReadFile(filepath.Join(prepared.bundle, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec ociSpec
	if err := json.Unmarshal(content, &spec); err != nil {
		t.Fatal(err)
	}
	mount := findMount(t, spec.Mounts, "/runtime")
	if mount.Source != runtimeRoot || !containsAll(mount.Options, "bind", "ro", "nosuid", "nodev") || slices.Contains(mount.Options, "noexec") {
		t.Errorf("runtime mount = %#v", mount)
	}

	outside := t.TempDir()
	workload.ReadOnlyMounts[0].Source = outside
	if _, err := provider.ResolveWorkload(context.Background(), execution.Request{JobID: "job-1", Limits: execution.Limits{MaxOutputBytes: 1024}}, workload); err == nil {
		t.Error("outside mount ResolveWorkload() error = nil")
	}
	siblingRuntime := filepath.Join(roots.inputs, "job-2", "runtime")
	if err := os.MkdirAll(siblingRuntime, 0o700); err != nil {
		t.Fatal(err)
	}
	workload.ReadOnlyMounts[0].Source = siblingRuntime
	if _, err := provider.ResolveWorkload(context.Background(), execution.Request{JobID: "job-1", Limits: execution.Limits{MaxOutputBytes: 1024}}, workload); err == nil {
		t.Error("sibling-job mount ResolveWorkload() error = nil")
	}
	workload.ReadOnlyMounts[0].Source = runtimeRoot
	workload.ReadOnlyMounts[0].Destination = "/etc"
	if _, err := provider.ResolveWorkload(context.Background(), execution.Request{JobID: "job-1", Limits: execution.Limits{MaxOutputBytes: 1024}}, workload); err == nil {
		t.Error("unsafe destination ResolveWorkload() error = nil")
	}
}

func TestExecuteUsesHardenedRunscFlagsAndCollectsBoundedOutput(t *testing.T) {
	provider, runner, _ := testProvider(t)
	runner.run = func(_ context.Context, invocation command) commandResult {
		if commandVerb(invocation.Args) == "run" {
			_, _ = io.WriteString(invocation.Stdout, "hello\nthis output is deliberately long\n")
			_, _ = io.WriteString(invocation.Stderr, "secret-value\n")
		}
		return successResult()
	}
	config := validConfiguration()
	config.RedactSecrets = []string{"secret-value"}
	config.MaxLineBytes = 12
	prepared := prepareEnvironment(t, provider, config, 96)

	outcome, err := prepared.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if outcome.ExitCode == nil || *outcome.ExitCode != 0 || outcome.Failure != nil {
		t.Errorf("Execute() outcome = %#v", outcome)
	}
	attempt, err := readMetadata(filepath.Join(prepared.bundle, attemptName))
	if err != nil {
		t.Fatalf("read run-attempt metadata: %v", err)
	}
	if attempt.ContainerID != prepared.containerID || attempt.Phase != metadataPhaseAttempted {
		t.Errorf("run-attempt metadata = %#v", attempt)
	}
	bundle, err := prepared.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if strings.Contains(bundle.Stderr, "secret-value") || !strings.Contains(bundle.Stderr, evidence.RedactionMarker) {
		t.Errorf("stderr redaction = %q", bundle.Stderr)
	}
	if !bundle.OutputTruncated || bundle.CapturedBytes > 96 {
		t.Errorf("output bounds = captured %d, truncated %t", bundle.CapturedBytes, bundle.OutputTruncated)
	}

	commands := runner.commands()
	if len(commands) != 1 {
		t.Fatalf("runtime command count = %d", len(commands))
	}
	wantPrefix := []string{
		"--root=" + provider.config.StateRoot,
		"--network=none",
		"--overlay2=none",
		"--directfs=false",
		"--file-access=exclusive",
		"--file-access-mounts=exclusive",
		"--host-uds=none",
		"--host-fifo=none",
		"--character-device-policy=emulated-only",
		"--net-raw=false",
		"--allow-suid=false",
		"--platform=systrap",
		"--cpu-num-from-quota=true",
		"run",
		"--bundle=" + prepared.bundle,
		prepared.containerID,
	}
	if !reflect.DeepEqual(commands[0].Args, wantPrefix) {
		t.Errorf("runsc args = %#v, want %#v", commands[0].Args, wantPrefix)
	}
	if err := prepared.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	commands = runner.commands()
	if commandVerb(commands[1].Args) != "delete" || !slices.Contains(commands[1].Args, "--force") {
		t.Errorf("cleanup args = %#v", commands[1].Args)
	}
}

func TestTrustedWorkloadStructuredOutputReachesCollectedEvents(t *testing.T) {
	provider, runner, roots := testProvider(t)
	runner.run = func(_ context.Context, invocation command) commandResult {
		if commandVerb(invocation.Args) == "run" {
			_, _ = io.WriteString(invocation.Stdout, "ordinary log\nEVENT:{\"state\":\"ready\"}\n")
		}
		return successResult()
	}
	environment, err := provider.ResolveWorkload(context.Background(), execution.Request{JobID: "job-1", Limits: execution.Limits{MaxOutputBytes: 1024}}, execution.IsolatedWorkload{
		Command: "/bin/sh", Arguments: []string{"-c", "true"}, InputsPath: filepath.Join(roots.inputs, "job-1"), Network: "none",
		MemoryBytes: 256 << 20, CPUMillis: 1000, PIDs: 32, DiskBytes: 64 << 20,
		StructuredOutputPrefix: "EVENT:", StructuredOutputKind: "probe",
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := environment.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	output, err := prepared.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(output.StructuredEvents) != 1 || output.StructuredEvents[0].Kind != "probe" || string(output.StructuredEvents[0].Payload) != `{"state":"ready"}` || strings.Contains(output.Stdout, "EVENT:") {
		t.Fatalf("output = %#v", output)
	}
	if err := prepared.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteClassifiesSandboxedExitAndRuntimeFailure(t *testing.T) {
	t.Run("workload exit", func(t *testing.T) {
		provider, runner, _ := testProvider(t)
		exitCode := 17
		runner.run = func(context.Context, command) commandResult {
			return commandResult{ExitCode: &exitCode, Err: errors.New("exit status 17")}
		}
		prepared := prepareEnvironment(t, provider, validConfiguration(), 1024)
		outcome, err := prepared.Execute(context.Background())
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if outcome.Failure == nil || outcome.Failure.Classification != execution.ClassificationWorkloadFailure || outcome.Failure.Code != "gvisor_process_exit_nonzero" {
			t.Errorf("Execute() outcome = %#v", outcome)
		}
	})

	t.Run("runtime failure", func(t *testing.T) {
		provider, runner, _ := testProvider(t)
		exitCode := 128
		runner.run = func(context.Context, command) commandResult {
			return commandResult{ExitCode: &exitCode, Err: errors.New("exit status 128")}
		}
		prepared := prepareEnvironment(t, provider, validConfiguration(), 1024)
		outcome, err := prepared.Execute(context.Background())
		if err == nil || !strings.Contains(err.Error(), "exit status 128") || outcome.ExitCode == nil || *outcome.ExitCode != 128 {
			t.Fatalf("Execute() error = %v", err)
		}
	})
}

func TestCancellationKillsContainerAndCleanupDeletesIt(t *testing.T) {
	provider, runner, _ := testProvider(t)
	runner.run = func(ctx context.Context, invocation command) commandResult {
		if commandVerb(invocation.Args) == "run" {
			<-ctx.Done()
			return commandResult{Err: ctx.Err()}
		}
		return successResult()
	}
	prepared := prepareEnvironment(t, provider, validConfiguration(), 1024)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := prepared.Execute(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute() error = %v, want context.Canceled", err)
	}
	if err := prepared.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	verbs := commandVerbs(runner.commands())
	if !reflect.DeepEqual(verbs, []string{"run", "kill", "delete"}) {
		t.Errorf("runtime verbs = %#v", verbs)
	}
	commands := runner.commands()
	if !slices.Contains(commands[1].Args, "--all") || commands[1].Args[len(commands[1].Args)-1] != "KILL" {
		t.Errorf("kill args = %#v", commands[1].Args)
	}
}

func TestExecutorWallTimeoutKillsAndCleansContainer(t *testing.T) {
	provider, runner, _ := testProvider(t)
	runner.run = func(ctx context.Context, invocation command) commandResult {
		if commandVerb(invocation.Args) == "run" {
			<-ctx.Done()
			return commandResult{Err: ctx.Err()}
		}
		return successResult()
	}
	registry, err := execution.NewRegistry(provider)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := execution.NewExecutor(registry, execution.ExecutorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(validConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	result := executor.Execute(context.Background(), localjob.Job{
		SchemaVersion:       localjob.SchemaVersion,
		ID:                  "job-1",
		Provider:            ProviderName,
		TimeoutMilliseconds: 250,
		MaxOutputBytes:      1024,
		Environment:         content,
	})
	if result.Classification != execution.ClassificationTimedOut || result.Failure == nil || result.Failure.Code != "job_timeout" {
		t.Fatalf("executor result = %#v", result)
	}
	if result.Cleanup == nil || !result.Cleanup.Succeeded {
		t.Errorf("cleanup result = %#v", result.Cleanup)
	}
	if verbs := commandVerbs(runner.commands()); !reflect.DeepEqual(verbs, []string{"run", "kill", "delete"}) {
		t.Errorf("runtime verbs = %#v", verbs)
	}
}

func TestCleanupRetainsBundleForRetryWhenDeleteFails(t *testing.T) {
	provider, runner, _ := testProvider(t)
	deleteAttempts := 0
	runner.run = func(_ context.Context, invocation command) commandResult {
		if commandVerb(invocation.Args) == "delete" {
			deleteAttempts++
			if deleteAttempts == 1 {
				return commandResult{Err: errors.New("runtime unavailable")}
			}
		}
		return successResult()
	}
	prepared := prepareEnvironment(t, provider, validConfiguration(), 1024)
	if err := prepared.markRunAttempted(); err != nil {
		t.Fatalf("markRunAttempted() error = %v", err)
	}
	if err := prepared.Cleanup(context.Background()); err == nil {
		t.Fatal("Cleanup() error = nil")
	}
	if _, err := os.Stat(prepared.bundle); err != nil {
		t.Fatalf("bundle removed after failed delete: %v", err)
	}
	if err := prepared.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() retry error = %v", err)
	}
	if _, err := os.Stat(prepared.bundle); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bundle still exists after retry: %v", err)
	}
	if err := prepared.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() idempotent error = %v", err)
	}
	if deleteAttempts != 2 {
		t.Errorf("delete attempts = %d", deleteAttempts)
	}
}

func TestResolveRejectsUnsafeOrUnboundedConfiguration(t *testing.T) {
	provider, _, _ := testProvider(t)
	tests := map[string]func(*configuration){
		"relative command":   func(config *configuration) { config.Command = "java" },
		"null command":       func(config *configuration) { config.Command = "/bin/sh\x00" },
		"host network":       func(config *configuration) { config.Network = "host" },
		"missing memory":     func(config *configuration) { config.MemoryBytes = 0 },
		"excess memory":      func(config *configuration) { config.MemoryBytes = 65 << 30 },
		"missing CPU":        func(config *configuration) { config.CPUMillis = 0 },
		"excess CPU":         func(config *configuration) { config.CPUMillis = 64_001 },
		"missing PID limit":  func(config *configuration) { config.PIDs = 0 },
		"excess PID limit":   func(config *configuration) { config.PIDs = 4_097 },
		"missing disk limit": func(config *configuration) { config.DiskBytes = 0 },
		"excess disk limit":  func(config *configuration) { config.DiskBytes = 65 << 30 },
		"invalid env key":    func(config *configuration) { config.Environment["BAD=KEY"] = "x" },
		"empty secret":       func(config *configuration) { config.RedactSecrets = []string{""} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validConfiguration()
			mutate(&config)
			content, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.Resolve(context.Background(), execution.Request{JobID: "job-1", Environment: content, Limits: execution.Limits{MaxOutputBytes: 1024}})
			if err == nil {
				t.Fatal("Resolve() error = nil")
			}
		})
	}

	content, _ := json.Marshal(validConfiguration())
	for _, jobID := range []string{"", "../escape", "has/slash", strings.Repeat("a", 129)} {
		if _, err := provider.Resolve(context.Background(), execution.Request{JobID: jobID, Environment: content, Limits: execution.Limits{MaxOutputBytes: 1024}}); err == nil {
			t.Errorf("Resolve(job ID %q) error = nil", jobID)
		}
	}
	unknown := append(content[:len(content)-1], []byte(`,"unknown":true}`)...)
	if _, err := provider.Resolve(context.Background(), execution.Request{JobID: "job-1", Environment: unknown, Limits: execution.Limits{MaxOutputBytes: 1024}}); err == nil {
		t.Error("Resolve(unknown field) error = nil")
	}
}

func TestNewProviderValidatesTrustedConfiguration(t *testing.T) {
	root := t.TempDir()
	rootFS := filepath.Join(root, "rootfs")
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(rootFS, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(inputs, 0o700); err != nil {
		t.Fatal(err)
	}
	base := Config{RunscPath: "runsc", RootFS: rootFS, RootFSIdentity: "test-rootfs", runtimeIdentity: "test-runsc", InputsRoot: inputs, StateRoot: filepath.Join(root, "state"), BundleRoot: filepath.Join(root, "bundles")}
	for name, mutate := range map[string]func(*Config){
		"missing runsc":            func(config *Config) { config.RunscPath = "" },
		"missing rootfs":           func(config *Config) { config.RootFS = filepath.Join(root, "missing") },
		"missing inputs":           func(config *Config) { config.InputsRoot = filepath.Join(root, "missing") },
		"empty state":              func(config *Config) { config.StateRoot = "" },
		"empty bundles":            func(config *Config) { config.BundleRoot = "" },
		"bad platform":             func(config *Config) { config.Platform = "ptrace" },
		"missing rootfs identity":  func(config *Config) { config.RootFSIdentity = "" },
		"missing runtime identity": func(config *Config) { config.runtimeIdentity = "" },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := newProvider(config, &fakeCommandRunner{}); err == nil {
				t.Fatal("newProvider() error = nil")
			}
		})
	}
	t.Run("overlapping trusted roots", func(t *testing.T) {
		config := base
		config.BundleRoot = filepath.Join(rootFS, "bundles")
		if _, err := newProvider(config, &fakeCommandRunner{}); err == nil || !strings.Contains(err.Error(), "must not overlap") {
			t.Fatalf("newProvider() error = %v", err)
		}
	})
}

type testRoots struct {
	rootFS string
	inputs string
}

func testProvider(t *testing.T) (*Provider, *fakeCommandRunner, testRoots) {
	t.Helper()
	root := t.TempDir()
	rootFS := filepath.Join(root, "rootfs")
	inputs := filepath.Join(root, "inputs")
	jobInputs := filepath.Join(inputs, "job-1")
	for _, directory := range []string{rootFS, inputs, jobInputs} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("Mkdir(%q) error = %v", directory, err)
		}
	}
	runner := &fakeCommandRunner{}
	provider, err := newProvider(Config{
		RunscPath:       "runsc",
		RootFS:          rootFS,
		StateRoot:       filepath.Join(root, "state"),
		BundleRoot:      filepath.Join(root, "bundles"),
		InputsRoot:      inputs,
		Platform:        "systrap",
		RootFSIdentity:  "test-rootfs",
		runtimeIdentity: "test-runsc",
	}, runner)
	if err != nil {
		t.Fatalf("newProvider() error = %v", err)
	}
	return provider, runner, testRoots{rootFS: rootFS, inputs: inputs}
}

func validConfiguration() configuration {
	return configuration{
		Command:      "/usr/bin/java",
		Arguments:    []string{"-jar", "/inputs/server.jar"},
		Environment:  map[string]string{"Z": "last", "A": "first"},
		Network:      "none",
		MemoryBytes:  256 << 20,
		CPUMillis:    1500,
		PIDs:         64,
		DiskBytes:    32 << 20,
		MaxLineBytes: 1024,
	}
}

func resolveEnvironment(t *testing.T, provider *Provider, config configuration, outputLimit int64) execution.Environment {
	t.Helper()
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := provider.Resolve(context.Background(), execution.Request{
		JobID:       "job-1",
		Environment: content,
		Limits:      execution.Limits{MaxOutputBytes: outputLimit},
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	return environment
}

func prepareEnvironment(t *testing.T, provider *Provider, config configuration, outputLimit int64) *preparedEnvironment {
	t.Helper()
	environment := resolveEnvironment(t, provider, config, outputLimit)
	prepared, err := environment.Prepare(context.Background())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	return prepared.(*preparedEnvironment)
}

func findMount(t *testing.T, mounts []ociMount, destination string) ociMount {
	t.Helper()
	for _, mount := range mounts {
		if mount.Destination == destination {
			return mount
		}
	}
	t.Fatalf("mount %q not found", destination)
	return ociMount{}
}

func containsAll(values []string, expected ...string) bool {
	for _, value := range expected {
		if !slices.Contains(values, value) {
			return false
		}
	}
	return true
}

type fakeCommandRunner struct {
	mu          sync.Mutex
	invocations []command
	run         func(context.Context, command) commandResult
}

func (r *fakeCommandRunner) Run(ctx context.Context, invocation command) commandResult {
	r.mu.Lock()
	r.invocations = append(r.invocations, invocation)
	run := r.run
	r.mu.Unlock()
	if run != nil {
		return run(ctx, invocation)
	}
	return successResult()
}

func (r *fakeCommandRunner) commands() []command {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]command(nil), r.invocations...)
}

func successResult() commandResult {
	exitCode := 0
	return commandResult{ExitCode: &exitCode}
}

func commandVerb(arguments []string) string {
	for _, argument := range arguments {
		switch argument {
		case "run", "kill", "delete":
			return argument
		}
	}
	return ""
}

func commandVerbs(commands []command) []string {
	verbs := make([]string, len(commands))
	for index, command := range commands {
		verbs[index] = commandVerb(command.Args)
	}
	return verbs
}

func TestExecuteCancellationDoesNotWaitForParentDeadlineDuringKill(t *testing.T) {
	provider, runner, _ := testProvider(t)
	runner.run = func(ctx context.Context, invocation command) commandResult {
		if commandVerb(invocation.Args) == "run" {
			<-ctx.Done()
			return commandResult{Err: ctx.Err()}
		}
		if ctx.Err() != nil {
			t.Errorf("detached kill context error = %v", ctx.Err())
		}
		return successResult()
	}
	prepared := prepareEnvironment(t, provider, validConfiguration(), 1024)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	_, _ = prepared.Execute(ctx)
	if !slices.Contains(commandVerbs(runner.commands()), "kill") {
		t.Error("kill was not attempted")
	}
}
