//go:build linux

package gvisor_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/provider/gvisor"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	"github.com/bwmp-dev/provenance-runner/internal/workspace"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRunscSmokeNoNetworkV2(t *testing.T) {
	if os.Getenv("PROVENANCE_RUNSC_SMOKE") != "1" || os.Getenv("PROVENANCE_MEASURED_ROOTFS_IMAGE") == "" {
		t.Skip("disposable measured systemd fixture required")
	}
	if os.Getuid() == 0 || os.Getenv("PROVENANCE_GVISOR_CGROUP_DRIVER") != "systemd-user" {
		t.Fatal("disposable non-root systemd provider required")
	}
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := io.ReadAll(io.LimitReader(self, (64<<20)+1))
	self.Close()
	if err != nil || len(executable) > 64<<20 {
		t.Fatal("bounded synthetic executable")
	}
	archive := func(name string, data []byte, mode int64) []byte {
		var raw bytes.Buffer
		compressed := gzip.NewWriter(&raw)
		files := tar.NewWriter(compressed)
		if files.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg}) != nil {
			t.Fatal("fixture archive")
		}
		if _, err := files.Write(data); err != nil {
			t.Fatal(err)
		}
		if files.Close() != nil || compressed.Close() != nil {
			t.Fatal("fixture archive close")
		}
		return raw.Bytes()
	}
	payloads := map[string][]byte{"/java": archive("fixture-jre/bin/java", executable, 0755), "/paper": []byte("synthetic paper"), "/probe": []byte("synthetic probe"), "/prepared": archive("cache/patched.jar", []byte("synthetic prepared"), 0600), "/target": []byte("synthetic target")}
	server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, request *http.Request) {
		if value, ok := payloads[request.URL.Path]; ok {
			out.Write(value)
		} else {
			http.NotFound(out, request)
		}
	}))
	defer server.Close()
	client := server.Client()
	transport := client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	transport.TLSClientConfig.ServerName = "example.com"
	const origin = "https://93.184.216.34"
	pin := func(path, name string) paper.ArtifactPin {
		return paper.ArtifactPin{URI: origin + path, SHA256: artifact.SHA256(payloads[path]).String(), Filename: name, SizeBytes: int64(len(payloads[path]))}
	}
	catalog := paper.Catalog{EnvironmentID: "none-v2-fixture", Paper: paper.PaperPin{GameVersion: "1.21.8", Build: 60, Artifact: pin("/paper", "paper.jar")}, Java: paper.JavaPin{Distribution: "eclipse-temurin", Version: "21.0.8+9", OS: "linux", Architecture: "amd64", ArchiveRoot: "fixture-jre", Artifact: pin("/java", "java.tar.gz"), MaximumExpandedBytes: 128 << 20}, ProbeVersion: "test", ProbeSourceCommit: "test", Probe: pin("/probe", "probe.jar"), PreparedRuntime: paper.ArchivePin{Artifact: pin("/prepared", "prepared.tar.gz"), MaximumExpandedBytes: 1 << 20}}
	digest := func(raw []byte) *p.Digest {
		sum := sha256.Sum256(raw)
		return &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: sum[:]}
	}
	for _, secrets := range []bool{false, true} {
		name := "plain"
		if secrets {
			name = "secrets"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			root := t.TempDir()
			inputs := filepath.Join(root, "inputs")
			manager, err := workspace.NewManager(inputs)
			if err != nil {
				t.Fatal(err)
			}
			cache, err := artifact.NewCache(filepath.Join(root, "cache"), artifact.CacheOptions{MaximumEntryBytes: 64 << 20, MaximumTotalBytes: 128 << 20})
			if err != nil {
				t.Fatal(err)
			}
			image, err := os.Open(os.Getenv("PROVENANCE_MEASURED_ROOTFS_IMAGE"))
			if err != nil {
				t.Fatal(err)
			}
			imageHash := sha256.New()
			imageBytes, hashErr := io.Copy(imageHash, io.LimitReader(image, (512<<20)+1))
			closeErr := image.Close()
			if hashErr != nil || closeErr != nil || imageBytes == 0 || imageBytes > 512<<20 {
				t.Fatal("bounded fixture image hash")
			}
			sandbox, err := gvisor.New(gvisor.Config{RunscPath: os.Getenv("PROVENANCE_RUNSC_PATH"), CgroupDriver: "systemd-user", SystemdRunPath: os.Getenv("PROVENANCE_SYSTEMD_RUN_PATH"), SystemdCgroupRoot: os.Getenv("PROVENANCE_SYSTEMD_CGROUP_ROOT"), RootFS: os.Getenv("PROVENANCE_RUNSC_ROOTFS"), RootFSImagePath: os.Getenv("PROVENANCE_MEASURED_ROOTFS_IMAGE"), RootFSLoopDevicePath: os.Getenv("PROVENANCE_MEASURED_LOOP_DEVICE"), MeasuredRuntimeMode: "embedded-executable", RootFSIdentity: "sha256:" + hex.EncodeToString(imageHash.Sum(nil)), StateRoot: filepath.Join(root, "state"), BundleRoot: filepath.Join(root, "bundles"), InputsRoot: inputs, Platform: "systrap"})
			if err != nil || sandbox.Reconcile(ctx) != nil {
				t.Fatal("isolated provider", err)
			}
			provider, err := paper.New(paper.Config{Catalog: catalog, HTTPClient: client, ArtifactHosts: []string{"93.184.216.34"}, ArtifactCache: cache, JavaCache: cache, PaperCache: cache, ProbeCache: cache, RuntimeCache: cache, Workspaces: manager, Sandbox: sandbox, MaximumArtifactBytes: 64 << 20, MaximumDependencyBytes: 64 << 20, MaximumPreparationBytes: 256 << 20})
			if err != nil {
				t.Fatal(err)
			}
			config := map[string]any{"apiVersion": "provenance.dev/v2", "project": map[string]any{"id": "none-fixture", "name": "NoneFixture"}, "artifact": map[string]any{"id": "none-fixture", "path": "build/none.jar", "version": "1.0.0"}, "dependencies": []any{}, "network": map[string]any{"mode": "none", "permissions": []any{}, "maximumConnections": 0, "maximumBytesPerSecond": 0}, "release": map[string]any{"mode": "test-only", "targets": []any{}}, "paper": map[string]any{"matrix": []any{map[string]any{"id": "paper", "minecraftVersion": "1.21.8", "paperBuild": 60, "javaVersion": 21, "policy": "required"}}, "recommendations": map[string]any{"apiFloor": "1.21.8", "enabled": false, "newVersions": "informational"}, "gatePolicy": map[string]any{"informationalFailure": "report", "infrastructureFailure": "retry", "maxInfrastructureRetries": 2, "requiredFailure": "block"}}, "tests": map[string]any{"startup": map[string]any{"timeoutSeconds": 20, "stabilizationSeconds": 1, "requirePluginEnabled": true, "shutdownTimeoutSeconds": 1, "requireCleanShutdown": true}, "console": []any{}}, "resources": map[string]any{"cpuCores": 1, "memoryMiB": 1024, "diskMiB": 256, "processes": 64, "wallTimeoutSeconds": 20, "logBytes": 1 << 20}}
			job := &p.JobSpecification{Lease: &p.LeaseIdentity{JobId: "a1111111-1111-4111-8111-111111111111", LeaseId: "a2222222-2222-4222-8222-222222222222", ExecutionId: "a3333333-3333-4333-8333-333333333333", ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}, Attempt: &p.AttemptIdentity{AttemptId: "a4444444-4444-4444-8444-444444444444", ReleaseCandidateId: "a5555555-5555-4555-8555-555555555555", MatrixEntryId: "a6666666-6666-4666-8666-666666666666", AttemptNumber: 1}, TargetPluginName: "NoneFixture", Environment: &p.ResolvedEnvironment{Provider: p.ServerProvider_SERVER_PROVIDER_PAPER, GameVersion: "1.21.8", ServerVersion: "1.21.8", ServerBuild: 60, JavaDistribution: "eclipse-temurin", JavaVersion: "21.0.8+9", OperatingSystem: p.OperatingSystem_OPERATING_SYSTEM_LINUX, Architecture: p.Architecture_ARCHITECTURE_AMD64, ServerBinary: digest(payloads["/paper"])}, EffectivePolicy: &p.EffectivePolicy{Sandbox: p.SandboxKind_SANDBOX_KIND_GVISOR, Requirement: p.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED, NetworkV2: &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_NONE}, Resources: &p.ResourceLimits{CpuMillis: 1000, MemoryBytes: 1 << 30, DiskBytes: 256 << 20, ProcessCount: 64}, PreparationTimeout: durationpb.New(20 * time.Second), ExecutionTimeout: durationpb.New(20 * time.Second), GracefulShutdownTimeout: durationpb.New(time.Second)}, Artifact: &p.ObjectDownload{Uri: origin + "/target", Filename: "target.jar", Digest: digest(payloads["/target"]), SizeBytes: int64(len(payloads["/target"]))}}
			calls := 0
			if secrets {
				config["tests"].(map[string]any)["secrets"] = map[string]uint64{"license": 1}
				job.TestSecrets = []*p.TestSecretReference{{Name: "license", SecretId: "b1111111-1111-4111-8111-111111111111", Version: 1}}
				ctx = execution.WithTestSecretSource(ctx, func(context.Context) (*ts.Files, time.Time, error) {
					calls++
					files, err := ts.New([]ts.Input{{Name: "license", Value: []byte("synthetic-none-v2-secret")}})
					return files, time.Now().Add(30 * time.Second), err
				})
			}
			job.NormalizedConfigurationJson, err = json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			environment, err := proto.MarshalOptions{Deterministic: true}.Marshal(job.Environment)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := np.EffectivePolicyV2SHA256(job.EffectivePolicy)
			if err != nil {
				t.Fatal(err)
			}
			job.Hashes = &p.JobHashes{Artifact: job.Artifact.Digest, Configuration: digest(job.NormalizedConfigurationJson), Environment: digest(environment), Policy: &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: policy[:]}}
			local, err := provider.AdaptNoNetworkV2(job)
			if err != nil {
				t.Fatal(err)
			}
			registry, err := execution.NewRegistry(provider)
			if err != nil {
				t.Fatal(err)
			}
			executor, err := execution.NewExecutor(registry, execution.ExecutorOptions{TerminalEvidenceV2: true})
			if err != nil {
				t.Fatal(err)
			}
			result := executor.Execute(ctx, local)
			if result.CompleteLog != nil && result.CompleteLog.Archive != nil {
				defer result.CompleteLog.Archive.Close()
			}
			if result.Classification != execution.ClassificationPassed || result.Cleanup == nil || !result.Cleanup.Succeeded || result.MeasuredRuntime == nil || !result.MeasuredRuntime.Valid() || result.MeasuredRuntime.NetworkMode != "none" || result.MeasuredNetwork != nil || result.Logs == nil || !strings.Contains(result.Logs.Stdout, "NONE_V2_OK") {
				t.Fatalf("isolated v2 execution: class=%s failure=%v cleanup=%v", result.Classification, result.Failure, result.Cleanup)
			}
			if secrets && (calls != 1 || strings.Contains(result.Logs.Stdout, "synthetic-none-v2-secret") || !strings.Contains(result.Logs.Stdout, evidence.RedactionMarker) || !strings.Contains(result.Logs.Stdout, "NONE_V2_SECRET_OK")) {
				t.Fatal("no-network secret source/redaction")
			}
			result.TerminalContext, err = terminalevidence.NewContextV2(job)
			if err != nil {
				t.Fatal(err)
			}
			frozen, err := result.FreezeTerminalEvidence("none-fixture")
			if err != nil || terminalevidence.ValidateFrozenV2(frozen, job, "none-fixture") != nil {
				t.Fatal("original v2 evidence binding")
			}
			if sandbox.Reconcile(ctx) != nil || manager.ReconcileOwnedAttempts(ctx) != nil {
				t.Fatal("no-network retirement")
			}
		})
	}
}
