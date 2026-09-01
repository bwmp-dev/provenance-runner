package paper

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	"github.com/bwmp-dev/provenance-runner/internal/workspace"
)

func TestPrepareBuildsPinnedEphemeralPaperWorkspace(t *testing.T) {
	runtimeArchive := testRuntimeArchive(t, "test-jre")
	payloads := map[string][]byte{
		"/paper":      []byte("pinned Paper server"),
		"/java":       runtimeArchive,
		"/target":     []byte("safe success fixture jar"),
		"/probe":      []byte("safe Paper probe jar"),
		"/dependency": []byte("safe dependency jar"),
	}
	server, requests := artifactServer(t, payloads)
	sandbox := &fakeSandboxProvider{prepared: &fakePrepared{}}
	provider := testProvider(t, server, sandbox, payloads, "test-jre")
	config := validConfiguration(server.URL, payloads)

	environment := resolveTestEnvironment(t, provider, "paper-job-1", config)
	identity := environment.Identity()
	for _, component := range []string{artifact.SHA256(payloads["/paper"]).String(), artifact.SHA256(payloads["/java"]).String(), artifact.SHA256(payloads["/probe"]).String(), "delegate:gvisor/test/rootfs:test/runsc:test"} {
		if !strings.Contains(identity, component) {
			t.Fatalf("Identity() = %q; missing %q", identity, component)
		}
	}
	reporter, ok := environment.(execution.ResourceClassReporter)
	if !ok {
		t.Fatal("resolved environment does not report its resource class")
	}
	if got := reporter.ResourceClass(); got != (execution.ResourceClass{
		CPUMillis:    1500,
		MemoryBytes:  1 << 30,
		ProcessCount: 64,
		DiskBytes:    2 << 30,
		Network:      "none",
	}) {
		t.Fatalf("ResourceClass() = %#v", got)
	}
	prepared, err := environment.Prepare(context.Background())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	workload := sandbox.lastWorkload()
	workspaceRoot := workload.InputsPath
	if workload.Command != "/bin/sh" || workload.Network != "none" {
		t.Errorf("workload command/network = %q/%q", workload.Command, workload.Network)
	}
	if workload.StructuredOutputPrefix != probeEventPrefix || workload.StructuredOutputKind != probeEventKind {
		t.Errorf("structured output channel = %q/%q", workload.StructuredOutputPrefix, workload.StructuredOutputKind)
	}
	if workload.MemoryBytes != 1<<30 || workload.CPUMillis != 1500 || workload.PIDs != 64 || workload.DiskBytes != 2<<30 {
		t.Errorf("workload limits = %#v", workload)
	}
	if len(workload.ReadOnlyMounts) != 1 || workload.ReadOnlyMounts[0].Destination != "/runtime" || !workload.ReadOnlyMounts[0].Executable {
		t.Errorf("runtime mounts = %#v", workload.ReadOnlyMounts)
	}
	if !strings.Contains(strings.Join(workload.Arguments, "\n"), "cp -R /inputs/server/. /workspace/") {
		t.Errorf("workload does not seed writable workspace: %#v", workload.Arguments)
	}
	if !strings.Contains(strings.Join(workload.Arguments, "\n"), `if [ "$status" -eq 125 ]; then exit 126`) {
		t.Errorf("workload does not preserve reserved wrapper exit 125: %#v", workload.Arguments)
	}
	joinedArguments := strings.Join(workload.Arguments, "\x00")
	if strings.Contains(joinedArguments, "provenance.fixture.hostile.enabled") {
		t.Fatalf("default workload enabled hostile fixtures: %#v", workload.Arguments)
	}
	for _, expected := range []string{
		"/runtime/bin/java",
		"-Xms256M",
		"-Xmx768M",
		"-Dprovenance.probe.target=SuccessFixture",
		"-Dprovenance.probe.requiredDependencies=DependencyFixture",
		"-Dprovenance.probe.events=/workspace/provenance-probe-events.ndjson",
		"-Dprovenance.probe.testPlan=/workspace/provenance-test-plan.json",
		"-Dprovenance.probe.stabilizationMillis=25",
		"-Dprovenance.probe.requestShutdown=true",
		"/workspace/paper.jar",
		"--nogui",
	} {
		if !strings.Contains(joinedArguments, expected) {
			t.Errorf("workload arguments do not contain %q: %#v", expected, workload.Arguments)
		}
	}
	assertFileContent(t, filepath.Join(workspaceRoot, "server", "paper.jar"), payloads["/paper"])
	assertFileContent(t, filepath.Join(workspaceRoot, "server", "cache", "patched-runtime.jar"), []byte("prepared Paper runtime"))
	assertFileContent(t, filepath.Join(workspaceRoot, "server", "plugins", "target.jar"), payloads["/target"])
	assertFileContent(t, filepath.Join(workspaceRoot, "server", "plugins", "provenance-probe.jar"), payloads["/probe"])
	assertFileContent(t, filepath.Join(workspaceRoot, "server", "plugins", "dependency-000.jar"), payloads["/dependency"])
	assertFileContent(t, filepath.Join(workspaceRoot, "server", "eula.txt"), []byte("eula=true\n"))
	properties, err := os.ReadFile(filepath.Join(workspaceRoot, "server", "server.properties"))
	if err != nil || !bytes.Contains(properties, []byte("online-mode=false\n")) || !bytes.Contains(properties, []byte("server-port=0\n")) {
		t.Errorf("minimal server properties = %q, error = %v", properties, err)
	}
	plan, err := os.ReadFile(filepath.Join(workspaceRoot, "server", "provenance-test-plan.json"))
	if err != nil || !bytes.Contains(plan, []byte(`"targetPlugin": "SuccessFixture"`)) {
		t.Errorf("test plan = %q, error = %v", plan, err)
	}
	javaInfo, err := os.Stat(filepath.Join(workspaceRoot, "runtime", "test-jre", "bin", "java"))
	if err != nil || (runtime.GOOS != "windows" && javaInfo.Mode().Perm()&0o111 == 0) {
		t.Fatalf("extracted Java executable mode = %v, error = %v", javaInfo, err)
	}

	outcome, err := prepared.Execute(context.Background())
	if err != nil || outcome.ExitCode == nil || *outcome.ExitCode != 0 {
		t.Errorf("Execute() = %#v, %v", outcome, err)
	}
	if _, err := prepared.Collect(context.Background()); err != nil {
		t.Errorf("Collect() error = %v", err)
	}
	if err := prepared.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if _, err := os.Stat(workspaceRoot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("workspace remains after cleanup: %v", err)
	}
	if !sandbox.prepared.cleaned {
		t.Error("sandbox delegate was not cleaned")
	}

	gotRequests := requests.snapshot()
	if len(gotRequests) != len(payloads) {
		t.Fatalf("download requests = %#v", gotRequests)
	}
	for path, count := range gotRequests {
		if count != 1 {
			t.Errorf("request count for %s = %d", path, count)
		}
	}
}

func TestPrepareEnablesHostileFixturesOnlyFromTrustedProviderConfig(t *testing.T) {
	runtimeArchive := testRuntimeArchive(t, "test-jre")
	payloads := map[string][]byte{
		"/paper":  []byte("pinned Paper server"),
		"/java":   runtimeArchive,
		"/target": []byte("hostile fixture jar"),
		"/probe":  []byte("safe Paper probe jar"),
	}
	server, _ := artifactServer(t, payloads)
	sandbox := &fakeSandboxProvider{prepared: &fakePrepared{}}
	provider := testProvider(t, server, sandbox, payloads, "test-jre")
	provider.config.AllowHostileFixtures = true
	config := validConfiguration(server.URL, payloads)
	config.Dependencies = nil
	config.TestPlan.RequiredDependencies = nil

	environment := resolveTestEnvironment(t, provider, "hostile-fixture-job", config)
	prepared, err := environment.Prepare(context.Background())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	t.Cleanup(func() {
		if err := prepared.Cleanup(context.Background()); err != nil {
			t.Errorf("Cleanup() error = %v", err)
		}
	})
	arguments := sandbox.lastWorkload().Arguments
	const property = "-Dprovenance.fixture.hostile.enabled=true"
	count := 0
	for _, argument := range arguments {
		if argument == property {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("hostile fixture property count = %d, arguments = %#v", count, arguments)
	}
}

func TestRemoteEnvironmentCannotEnableHostileFixtures(t *testing.T) {
	provider, server, payloads := validationTestProvider(t)
	config := validConfiguration(server.URL, payloads)
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded[:len(encoded)-1], []byte(`,"allowHostileFixtures":true}`)...)
	if _, err := provider.Resolve(context.Background(), execution.Request{
		JobID:       "remote-hostile-fixture-attempt",
		Environment: encoded,
		Limits:      execution.Limits{MaxOutputBytes: 1 << 20},
	}); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Resolve(remote hostile opt-in) error = %v", err)
	}
}

func TestArtifactCachesAvoidRepeatDownloads(t *testing.T) {
	runtimeArchive := testRuntimeArchive(t, "test-jre")
	payloads := map[string][]byte{
		"/paper":  []byte("Paper"),
		"/java":   runtimeArchive,
		"/target": []byte("target"),
		"/probe":  []byte("probe"),
	}
	server, requests := artifactServer(t, payloads)
	sandbox := &fakeSandboxProvider{prepared: &fakePrepared{}}
	provider := testProvider(t, server, sandbox, payloads, "test-jre")
	config := validConfiguration(server.URL, payloads)
	config.Dependencies = nil
	config.TestPlan.RequiredDependencies = nil

	for _, jobID := range []string{"paper-job-1", "paper-job-2"} {
		environment := resolveTestEnvironment(t, provider, jobID, config)
		prepared, err := environment.Prepare(context.Background())
		if err != nil {
			t.Fatalf("Prepare(%s) error = %v", jobID, err)
		}
		if err := prepared.Cleanup(context.Background()); err != nil {
			t.Fatalf("Cleanup(%s) error = %v", jobID, err)
		}
		sandbox.prepared = &fakePrepared{}
	}
	for path, count := range requests.snapshot() {
		if count != 1 {
			t.Errorf("request count for %s = %d, want 1", path, count)
		}
	}
}

func TestPrepareRejectsDigestMismatchBeforeCreatingWorkspace(t *testing.T) {
	runtimeArchive := testRuntimeArchive(t, "test-jre")
	payloads := map[string][]byte{
		"/paper":  []byte("Paper"),
		"/java":   runtimeArchive,
		"/target": []byte("different target bytes"),
		"/probe":  []byte("probe"),
	}
	server, _ := artifactServer(t, payloads)
	sandbox := &fakeSandboxProvider{prepared: &fakePrepared{}}
	provider := testProvider(t, server, sandbox, payloads, "test-jre")
	config := validConfiguration(server.URL, payloads)
	config.Dependencies = nil
	config.TestPlan.RequiredDependencies = nil
	config.Target.SHA256 = artifact.SHA256([]byte("declared target bytes")).String()
	environment := resolveTestEnvironment(t, provider, "paper-job-1", config)
	prepared, err := environment.Prepare(context.Background())
	if !errors.Is(err, artifact.ErrDigestMismatch) || prepared != nil {
		t.Fatalf("Prepare() = %#v, %v; want digest mismatch without allocated workspace", prepared, err)
	}
	if len(sandbox.workloads) != 0 {
		t.Error("sandbox was resolved after digest mismatch")
	}
}

func TestPrepareStopsArtifactOneByteOverDeclarationWithoutCachingIt(t *testing.T) {
	payloads := map[string][]byte{
		"/paper": []byte("Paper"), "/java": testRuntimeArchive(t, "test-jre"), "/target": []byte("target-bytes"), "/probe": []byte("probe"),
	}
	server, requests := artifactServer(t, payloads)
	sandbox := &fakeSandboxProvider{prepared: &fakePrepared{}}
	provider := testProvider(t, server, sandbox, payloads, "test-jre")
	config := validConfiguration(server.URL, payloads)
	config.Dependencies = nil
	config.TestPlan.RequiredDependencies = nil
	config.Target.SizeBytes--
	prepared, err := resolveTestEnvironment(t, provider, "paper-job-size", config).Prepare(context.Background())
	if !errors.Is(err, artifact.ErrSizeMismatch) || prepared != nil {
		t.Fatalf("Prepare() = %#v, %v", prepared, err)
	}
	config.Target.SizeBytes++
	prepared, err = resolveTestEnvironment(t, provider, "paper-job-size-retry", config).Prepare(context.Background())
	if err != nil {
		t.Fatalf("Prepare() retry error = %v", err)
	}
	if err := prepared.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests.snapshot()["/target"] != 2 {
		t.Fatalf("target requests = %d, want 2", requests.snapshot()["/target"])
	}
}

func TestPreparationFailureReturnsWorkspaceCleanupOwnership(t *testing.T) {
	payloads := map[string][]byte{
		"/paper":  []byte("Paper"),
		"/java":   testRuntimeArchive(t, "actual-jre"),
		"/target": []byte("target"),
		"/probe":  []byte("probe"),
	}
	server, _ := artifactServer(t, payloads)
	sandbox := &fakeSandboxProvider{prepared: &fakePrepared{}}
	provider := testProvider(t, server, sandbox, payloads, "missing-jre")
	config := validConfiguration(server.URL, payloads)
	config.Dependencies = nil
	config.TestPlan.RequiredDependencies = nil
	prepared, err := resolveTestEnvironment(t, provider, "paper-job-1", config).Prepare(context.Background())
	if err == nil || prepared == nil {
		t.Fatalf("Prepare() = %#v, %v; want partial cleanup ownership", prepared, err)
	}
	root := prepared.(*preparedEnvironment).workspace.Root()
	if _, statErr := os.Stat(root); statErr != nil {
		t.Fatalf("partial workspace missing before cleanup: %v", statErr)
	}
	if cleanupErr := prepared.Cleanup(context.Background()); cleanupErr != nil {
		t.Fatalf("Cleanup() error = %v", cleanupErr)
	}
	if _, statErr := os.Stat(root); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("partial workspace remains after cleanup: %v", statErr)
	}
}

func TestCleanupAttemptsDelegateAndWorkspaceAndJoinsErrors(t *testing.T) {
	payloads := map[string][]byte{
		"/paper": []byte("Paper"), "/java": testRuntimeArchive(t, "test-jre"), "/target": []byte("target"), "/probe": []byte("probe"),
	}
	server, _ := artifactServer(t, payloads)
	delegate := &fakePrepared{cleanupErr: errors.New("delegate cleanup failed")}
	sandbox := &fakeSandboxProvider{prepared: delegate}
	provider := testProvider(t, server, sandbox, payloads, "test-jre")
	config := validConfiguration(server.URL, payloads)
	config.Dependencies = nil
	config.TestPlan.RequiredDependencies = nil
	prepared, err := resolveTestEnvironment(t, provider, "paper-job-cleanup", config).Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = prepared.Cleanup(ctx)
	if err == nil || !strings.Contains(err.Error(), "delegate cleanup failed") || !errors.Is(err, context.Canceled) || !delegate.cleaned {
		t.Fatalf("Cleanup() error/attempt = %v/%v", err, delegate.cleaned)
	}
	delegate.cleanupErr = nil
	if err := prepared.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() retry error = %v", err)
	}
}

func TestExecutorClassifiesFailedProbeAssertionWhenJVMExitsZero(t *testing.T) {
	payloads := map[string][]byte{
		"/paper": []byte("Paper"), "/java": testRuntimeArchive(t, "test-jre"), "/target": []byte("target"), "/probe": []byte("probe"),
	}
	server, _ := artifactServer(t, payloads)
	output := happyProbeOutput()
	replaceProbeEvent(t, &output, "TARGET_REQUIREMENT", `{"role":"TARGET","name":"SuccessFixture","configured":true,"loaded":true,"enabled":false}`)
	sandbox := &fakeSandboxProvider{prepared: &fakePrepared{output: &output}}
	provider := testProvider(t, server, sandbox, payloads, "test-jre")
	config := validConfiguration(server.URL, payloads)
	config.Dependencies = nil
	config.TestPlan.RequiredDependencies = nil
	environmentJSON, _ := json.Marshal(config)
	registry, err := execution.NewRegistry(provider)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := execution.NewExecutor(registry, execution.ExecutorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result := executor.Execute(context.Background(), localjob.Job{
		SchemaVersion:  localjob.SchemaVersion,
		ID:             "paper-probe-failure",
		Provider:       ProviderName,
		Environment:    environmentJSON,
		MaxOutputBytes: 1 << 20,
	})
	if result.Execution == nil || result.Execution.ExitCode == nil || *result.Execution.ExitCode != 0 || result.Classification != execution.ClassificationWorkloadFailure || result.Failure == nil || result.Failure.Code != "paper_lifecycle_failed" {
		t.Fatalf("result = %#v", result)
	}
}

func TestExecutorPreservesValidatedProbeFailureCode(t *testing.T) {
	payloads := map[string][]byte{
		"/paper": []byte("Paper"), "/java": testRuntimeArchive(t, "test-jre"), "/target": []byte("target"), "/probe": []byte("probe"),
	}
	server, _ := artifactServer(t, payloads)
	output := happyProbeOutput()
	failure := []execution.StructuredEvent{
		probeStructuredEvent(5, "LIFECYCLE_EXCEPTION", `{"phase":"LOAD","plugin":"SuccessFixture"}`),
		probeStructuredEvent(6, "CLASSIFICATION", `{"code":"on_load_failure","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_STARTUP","retryable":false,"plugin":"SuccessFixture"}`),
	}
	output.StructuredEvents = append(output.StructuredEvents[:4], append(failure, output.StructuredEvents[4:]...)...)
	sandbox := &fakeSandboxProvider{prepared: &fakePrepared{output: &output}}
	provider := testProvider(t, server, sandbox, payloads, "test-jre")
	config := validConfiguration(server.URL, payloads)
	config.Dependencies = nil
	config.TestPlan.RequiredDependencies = nil
	environmentJSON, _ := json.Marshal(config)
	registry, err := execution.NewRegistry(provider)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := execution.NewExecutor(registry, execution.ExecutorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result := executor.Execute(context.Background(), localjob.Job{
		SchemaVersion:  localjob.SchemaVersion,
		ID:             "paper-probe-classification",
		Provider:       ProviderName,
		Environment:    environmentJSON,
		MaxOutputBytes: 1 << 20,
	})
	if result.Classification != execution.ClassificationWorkloadFailure || result.Failure == nil || result.Failure.Code != "on_load_failure" {
		t.Fatalf("result = %#v", result)
	}
}

func TestExecutorClassifiesPaperWorkspaceSeedFailureAsInfrastructure(t *testing.T) {
	payloads := map[string][]byte{
		"/paper": []byte("Paper"), "/java": testRuntimeArchive(t, "test-jre"), "/target": []byte("target"), "/probe": []byte("probe"),
	}
	server, _ := artifactServer(t, payloads)
	exitCode := workspaceSeedFailureExitCode
	sandbox := &fakeSandboxProvider{prepared: &fakePrepared{
		outcome: &execution.ExecutionOutcome{
			ExitCode: &exitCode,
			Failure:  execution.NewFailure(execution.ClassificationWorkloadFailure, "gvisor_process_exit_nonzero", "sandboxed process exited with code 125"),
		},
		output: &execution.CollectedOutput{},
	}}
	provider := testProvider(t, server, sandbox, payloads, "test-jre")
	config := validConfiguration(server.URL, payloads)
	config.Dependencies = nil
	config.TestPlan.RequiredDependencies = nil
	environmentJSON, _ := json.Marshal(config)
	registry, err := execution.NewRegistry(provider)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := execution.NewExecutor(registry, execution.ExecutorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result := executor.Execute(context.Background(), localjob.Job{
		SchemaVersion: localjob.SchemaVersion,
		ID:            "paper-seed-failure",
		Provider:      ProviderName,
		Environment:   environmentJSON,
	})
	if result.Execution == nil || result.Execution.ExitCode == nil || *result.Execution.ExitCode != workspaceSeedFailureExitCode || result.Classification != execution.ClassificationInfrastructureFailure || result.Failure == nil || result.Failure.Code != "paper_workspace_seed_failed" {
		t.Fatalf("result = %#v", result)
	}
	if result.Logs == nil || result.Logs.Error != "" {
		t.Fatalf("collection masked seed failure: %#v", result.Logs)
	}
}

func TestResolveFailsClosedForUnsupportedOrAmbiguousInput(t *testing.T) {
	provider, server, payloads := validationTestProvider(t)
	base := validConfiguration(server.URL, payloads)
	tests := map[string]func(*configuration){
		"artifact kind":           func(config *configuration) { config.ArtifactKind = "generic-jar" },
		"environment pin":         func(config *configuration) { config.EnvironmentID = "paper-latest" },
		"target plugin":           func(config *configuration) { config.TestPlan.TargetPlugin = "../target" },
		"memory":                  func(config *configuration) { config.MemoryBytes = 1 },
		"dependency plugin":       func(config *configuration) { config.Dependencies[0].Plugin = "../dependency" },
		"unconfigured required":   func(config *configuration) { config.TestPlan.RequiredDependencies = []string{"Missing"} },
		"non-jar target":          func(config *configuration) { config.Target.Filename = "target.zip" },
		"non-https target":        func(config *configuration) { config.Target.URI = "http://example.test/target.jar" },
		"invalid target digest":   func(config *configuration) { config.Target.SHA256 = "bad" },
		"missing target size":     func(config *configuration) { config.Target.SizeBytes = 0 },
		"insufficient disk quota": func(config *configuration) { config.DiskBytes = 1 << 20 },
		"negative stabilization":  func(config *configuration) { config.TestPlan.StabilizationMilliseconds = -1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := base
			config.Dependencies = append([]dependencyReference(nil), base.Dependencies...)
			config.TestPlan.RequiredDependencies = append([]string(nil), base.TestPlan.RequiredDependencies...)
			mutate(&config)
			content, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.Resolve(context.Background(), execution.Request{JobID: "job", Environment: content, Limits: execution.Limits{MaxOutputBytes: 1024}}); err == nil {
				t.Fatal("Resolve() error = nil")
			}
		})
	}
	content, _ := json.Marshal(base)
	unknown := append(content[:len(content)-1], []byte(`,"unknown":true}`)...)
	if _, err := provider.Resolve(context.Background(), execution.Request{JobID: "job", Environment: unknown, Limits: execution.Limits{MaxOutputBytes: 1024}}); err == nil {
		t.Error("Resolve(unknown field) error = nil")
	}
	probeSubstitution := append(content[:len(content)-1], []byte(`,"probe":{"uri":"https://attacker.example/probe.jar","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","filename":"probe.jar","sizeBytes":1}}`)...)
	if _, err := provider.Resolve(context.Background(), execution.Request{JobID: "job", Environment: probeSubstitution, Limits: execution.Limits{MaxOutputBytes: 1024}}); err == nil {
		t.Error("Resolve(job-controlled probe) error = nil")
	}
}

func TestResolveEnforcesAggregatePreparationQuotas(t *testing.T) {
	provider, server, payloads := validationTestProvider(t)
	config := validConfiguration(server.URL, payloads)
	content, _ := json.Marshal(config)
	provider.config.MaximumDependencyBytes = int64(len(payloads["/dependency"]) - 1)
	if _, err := provider.Resolve(context.Background(), execution.Request{JobID: "job", Environment: content, Limits: execution.Limits{MaxOutputBytes: 1024}}); err == nil || !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("dependency quota Resolve() error = %v", err)
	}
	provider.config.MaximumDependencyBytes = defaultMaximumDependencyBytes
	provider.config.MaximumPreparationBytes = 1
	if _, err := provider.Resolve(context.Background(), execution.Request{JobID: "job", Environment: content, Limits: execution.Limits{MaxOutputBytes: 1024}}); err == nil || !strings.Contains(err.Error(), "preparation limit") {
		t.Fatalf("preparation quota Resolve() error = %v", err)
	}
}

func TestAlphaCatalogPinsStablePaperAndTemurin(t *testing.T) {
	catalog := AlphaCatalog()
	if catalog.EnvironmentID != AlphaEnvironmentID || catalog.Paper.GameVersion != "1.21.8" || catalog.Paper.Build != 60 {
		t.Errorf("Paper pin = %#v", catalog)
	}
	if catalog.Paper.Artifact.SHA256 != "8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e" {
		t.Errorf("Paper SHA-256 = %q", catalog.Paper.Artifact.SHA256)
	}
	if catalog.Java.Distribution != "eclipse-temurin" || catalog.Java.Version != "21.0.8+9" || catalog.Java.Artifact.SHA256 != "968c283e104059dae86ea1d670672a80170f27a39529d815843ec9c1f0fa2a03" {
		t.Errorf("Java pin = %#v", catalog.Java)
	}
	if catalog.ProbeVersion != AlphaProbeVersion || catalog.ProbeSourceCommit != AlphaProbeSourceCommit || catalog.Probe.SHA256 != AlphaProbeSHA256 || catalog.Probe.SizeBytes != AlphaProbeSizeBytes {
		t.Errorf("probe pin = %#v", catalog)
	}
	if !strings.HasPrefix(DownloadUserAgent, "Provenance-") || !strings.Contains(DownloadUserAgent, "github.com/bwmp-dev/provenance-runner") {
		t.Errorf("DownloadUserAgent = %q", DownloadUserAgent)
	}
}

func TestToolkitSafeArtifactsPreparation(t *testing.T) {
	targetPath := os.Getenv("PROVENANCE_SAFE_FIXTURE_JAR")
	probePath := os.Getenv("PROVENANCE_PAPER_PROBE_JAR")
	if targetPath == "" || probePath == "" {
		t.Skip("set PROVENANCE_SAFE_FIXTURE_JAR and PROVENANCE_PAPER_PROBE_JAR to exercise the sibling toolkit artifacts")
	}
	target, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read safe fixture: %v", err)
	}
	probe, err := os.ReadFile(probePath)
	if err != nil {
		t.Fatalf("read Paper probe: %v", err)
	}
	const expectedSuccessFixtureSHA256 = "b4a4d3786ffe84b2b6be9789f9dc4171b8870c570b821e4521ea963771ecd69d"
	if digest := artifact.SHA256(target).String(); digest != expectedSuccessFixtureSHA256 {
		t.Fatalf("safe fixture SHA-256 = %s, want toolkit manifest value %s", digest, expectedSuccessFixtureSHA256)
	}
	payloads := map[string][]byte{
		"/paper":  []byte("Paper preparation fixture"),
		"/java":   testRuntimeArchive(t, "test-jre"),
		"/target": target,
		"/probe":  probe,
	}
	server, _ := artifactServer(t, payloads)
	sandbox := &fakeSandboxProvider{prepared: &fakePrepared{}}
	provider := testProvider(t, server, sandbox, payloads, "test-jre")
	config := validConfiguration(server.URL, payloads)
	config.Dependencies = nil
	config.TestPlan.RequiredDependencies = nil
	prepared, err := resolveTestEnvironment(t, provider, "toolkit-safe-artifacts", config).Prepare(context.Background())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	root := sandbox.lastWorkload().InputsPath
	assertFileContent(t, filepath.Join(root, "server", "plugins", "target.jar"), target)
	assertFileContent(t, filepath.Join(root, "server", "plugins", "provenance-probe.jar"), probe)
	if err := prepared.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
}

func validationTestProvider(t *testing.T) (*Provider, *httptest.Server, map[string][]byte) {
	t.Helper()
	payloads := map[string][]byte{
		"/paper":      []byte("Paper"),
		"/java":       testRuntimeArchive(t, "test-jre"),
		"/target":     []byte("target"),
		"/probe":      []byte("probe"),
		"/dependency": []byte("dependency"),
	}
	server, _ := artifactServer(t, payloads)
	return testProvider(t, server, &fakeSandboxProvider{prepared: &fakePrepared{}}, payloads, "test-jre"), server, payloads
}

func testProvider(t *testing.T, server *httptest.Server, sandbox *fakeSandboxProvider, payloads map[string][]byte, javaRoot string) *Provider {
	t.Helper()
	if _, exists := payloads["/prepared-runtime"]; !exists {
		payloads["/prepared-runtime"] = testPreparedRuntimeArchive(t)
	}
	newCache := func() *artifact.Cache {
		cache, err := artifact.NewCache(t.TempDir(), artifact.CacheOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return cache
	}
	manager, err := workspace.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	catalog := Catalog{
		EnvironmentID: "test-paper-environment",
		Paper: PaperPin{GameVersion: "1.21.8", Build: 60, Artifact: ArtifactPin{
			URI: server.URL + "/paper", SHA256: artifact.SHA256(payloads["/paper"]).String(), Filename: "paper.jar", SizeBytes: int64(len(payloads["/paper"])),
		}},
		Java: JavaPin{Distribution: "eclipse-temurin", Version: "21.0.8+9", OS: "linux", Architecture: "amd64", ArchiveRoot: javaRoot, Artifact: ArtifactPin{
			URI: server.URL + "/java", SHA256: artifact.SHA256(payloads["/java"]).String(), Filename: "java.tar.gz", SizeBytes: int64(len(payloads["/java"])),
		}, MaximumExpandedBytes: 1 << 20},
		ProbeVersion:      "test",
		ProbeSourceCommit: "test",
		Probe:             ArtifactPin{URI: server.URL + "/probe", SHA256: artifact.SHA256(payloads["/probe"]).String(), Filename: "paper-probe.jar", SizeBytes: int64(len(payloads["/probe"]))},
		PreparedRuntime:   ArchivePin{Artifact: ArtifactPin{URI: server.URL + "/prepared-runtime", SHA256: artifact.SHA256(payloads["/prepared-runtime"]).String(), Filename: "prepared-runtime.tar.gz", SizeBytes: int64(len(payloads["/prepared-runtime"]))}, MaximumExpandedBytes: 1 << 20},
	}
	localDialer := dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	provider, err := New(Config{
		ArtifactCache:  newCache(),
		PaperCache:     newCache(),
		JavaCache:      newCache(),
		ProbeCache:     newCache(),
		RuntimeCache:   newCache(),
		Workspaces:     manager,
		Sandbox:        sandbox,
		Catalog:        catalog,
		HTTPClient:     server.Client(),
		inputPolicy:    testSourcePolicy{},
		pinPolicy:      testSourcePolicy{},
		sourceResolver: staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}},
		sourceDialer:   localDialer,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return provider
}

func validConfiguration(baseURL string, payloads map[string][]byte) configuration {
	configuration := configuration{
		ArtifactKind:  ArtifactKindMinecraftPlugin,
		EnvironmentID: "test-paper-environment",
		Target:        artifactReference{URI: baseURL + "/target", SHA256: artifact.SHA256(payloads["/target"]).String(), Filename: "success-1.0.0.jar", SizeBytes: int64(len(payloads["/target"]))},
		TestPlan: testPlan{
			TargetPlugin:              "SuccessFixture",
			RequiredDependencies:      []string{"DependencyFixture"},
			StabilizationMilliseconds: 25,
		},
		MemoryBytes:  1 << 30,
		CPUMillis:    1500,
		PIDs:         64,
		DiskBytes:    2 << 30,
		MaxLineBytes: 4096,
	}
	if dependency, exists := payloads["/dependency"]; exists {
		configuration.Dependencies = []dependencyReference{{
			ID: "dependency-one", Plugin: "DependencyFixture",
			Artifact: artifactReference{URI: baseURL + "/dependency", SHA256: artifact.SHA256(dependency).String(), Filename: "dependency.jar", SizeBytes: int64(len(dependency))},
		}}
	}
	return configuration
}

func resolveTestEnvironment(t *testing.T, provider *Provider, jobID string, config configuration) execution.Environment {
	t.Helper()
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := provider.Resolve(context.Background(), execution.Request{JobID: jobID, Environment: content, Limits: execution.Limits{MaxOutputBytes: 1 << 20}})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	return environment
}

type requestCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (c *requestCounter) snapshot() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	copy := make(map[string]int, len(c.counts))
	for key, value := range c.counts {
		copy[key] = value
	}
	return copy
}

func artifactServer(t *testing.T, payloads map[string][]byte) (*httptest.Server, *requestCounter) {
	t.Helper()
	requests := &requestCounter{counts: make(map[string]int)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.UserAgent() != DownloadUserAgent {
			t.Errorf("User-Agent = %q", request.UserAgent())
		}
		payload, exists := payloads[request.URL.Path]
		if !exists {
			http.NotFound(writer, request)
			return
		}
		requests.mu.Lock()
		requests.counts[request.URL.Path]++
		requests.mu.Unlock()
		_, _ = writer.Write(payload)
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func testRuntimeArchive(t *testing.T, root string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	gzipWriter.Header.ModTime = unixEpoch
	tarWriter := tar.NewWriter(gzipWriter)
	entries := []struct {
		name string
		mode int64
		data []byte
	}{
		{name: root + "/", mode: 0o755},
		{name: root + "/bin/", mode: 0o755},
		{name: root + "/bin/java", mode: 0o755, data: []byte("test Java executable")},
		{name: root + "/release", mode: 0o644, data: []byte(`JAVA_VERSION="21.0.8"`)},
	}
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: entry.mode, Size: int64(len(entry.data))}
		if strings.HasSuffix(entry.name, "/") {
			header.Typeflag = tar.TypeDir
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(entry.data) > 0 {
			if _, err := tarWriter.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func testPreparedRuntimeArchive(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	gzipWriter.Header.ModTime = unixEpoch
	tarWriter := tar.NewWriter(gzipWriter)
	content := []byte("prepared Paper runtime")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "cache/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.WriteHeader(&tar.Header{Name: "cache/patched-runtime.jar", Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

var unixEpoch = time.Unix(0, 0).UTC()

func assertFileContent(t *testing.T, path string, expected []byte) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	if !bytes.Equal(actual, expected) {
		t.Errorf("content at %q = %q, want %q", path, actual, expected)
	}
}

type fakeSandboxProvider struct {
	mu        sync.Mutex
	workloads []execution.IsolatedWorkload
	prepared  *fakePrepared
}

func (*fakeSandboxProvider) Identity() string { return "gvisor/test/rootfs:test/runsc:test" }

func (p *fakeSandboxProvider) ResolveWorkload(_ context.Context, _ execution.Request, workload execution.IsolatedWorkload) (execution.Environment, error) {
	p.mu.Lock()
	p.workloads = append(p.workloads, workload)
	prepared := p.prepared
	p.mu.Unlock()
	return &fakeSandboxEnvironment{prepared: prepared}, nil
}

func (p *fakeSandboxProvider) lastWorkload() execution.IsolatedWorkload {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.workloads[len(p.workloads)-1]
}

type fakeSandboxEnvironment struct {
	prepared execution.PreparedEnvironment
}

func (*fakeSandboxEnvironment) Identity() string { return "fake-sandbox" }

func (e *fakeSandboxEnvironment) Prepare(context.Context) (execution.PreparedEnvironment, error) {
	return e.prepared, nil
}

type fakePrepared struct {
	cleaned    bool
	outcome    *execution.ExecutionOutcome
	executeErr error
	output     *execution.CollectedOutput
	collectErr error
	cleanupErr error
}

type testSourcePolicy struct{}

type staticResolver struct {
	addresses []netip.Addr
	err       error
}

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.addresses...), r.err
}

func (testSourcePolicy) ValidateInitial(uri *url.URL) error  { return validateTestURL(uri) }
func (testSourcePolicy) ValidateRedirect(uri *url.URL) error { return validateTestURL(uri) }

func validateTestURL(uri *url.URL) error {
	if uri == nil || uri.Scheme != "https" || uri.Host == "" || uri.User != nil || uri.Fragment != "" {
		return errors.New("test artifact URL must be HTTPS without credentials or fragment")
	}
	return nil
}

func (p *fakePrepared) Execute(context.Context) (execution.ExecutionOutcome, error) {
	if p.outcome != nil || p.executeErr != nil {
		if p.outcome == nil {
			return execution.ExecutionOutcome{}, p.executeErr
		}
		return *p.outcome, p.executeErr
	}
	exitCode := 0
	return execution.ExecutionOutcome{ExitCode: &exitCode}, nil
}

func (p *fakePrepared) Collect(context.Context) (execution.CollectedOutput, error) {
	if p.output != nil {
		return *p.output, p.collectErr
	}
	output := happyProbeOutput()
	return output, p.collectErr
}

func (p *fakePrepared) Cleanup(context.Context) error {
	p.cleaned = true
	return p.cleanupErr
}

func happyProbeOutput() execution.CollectedOutput {
	events := []execution.StructuredEvent{
		probeStructuredEvent(1, "TEST_PLAN", `{"status":"LOADED","consoleTests":0,"maximumCommandOutputBytes":4096}`),
		probeStructuredEvent(2, "PROBE_LOADED", `{}`),
		probeStructuredEvent(3, "SERVER_LOADED", `{}`),
		probeStructuredEvent(4, "STABILIZATION_STARTED", `{}`),
		probeStructuredEvent(5, "TARGET_REQUIREMENT", `{"role":"TARGET","name":"SuccessFixture","configured":true,"loaded":true,"enabled":true}`),
		probeStructuredEvent(6, "TARGET_REQUIREMENT", `{"role":"REQUIRED_DEPENDENCY","name":"DependencyFixture","configured":true,"loaded":true,"enabled":true}`),
		probeStructuredEvent(7, "STABILIZATION_COMPLETED", `{}`),
		probeStructuredEvent(8, "SERVER_READY", `{"requirementsSatisfied":true}`),
		probeStructuredEvent(9, "CLEAN_SHUTDOWN_REQUESTED", `{}`),
		probeStructuredEvent(10, "SERVER_STOPPED", `{"shutdownRequested":true}`),
	}
	var eventBytes int64
	for _, event := range events {
		eventBytes += int64(len(event.Payload))
	}
	return execution.CollectedOutput{StructuredEvents: events, EvidenceUsage: execution.EvidenceUsage{StructuredEventCount: int64(len(events)), StructuredEventBytes: eventBytes}}
}

func probeStructuredEvent(sequence uint64, eventType, data string) execution.StructuredEvent {
	payload := fmt.Sprintf(`{"timestamp":"2026-08-30T00:00:00Z","type":%q,"data":%s}`, eventType, data)
	return execution.StructuredEvent{Sequence: sequence, Kind: probeEventKind, Payload: json.RawMessage(payload)}
}
