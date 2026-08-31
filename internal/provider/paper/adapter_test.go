package paper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestAdaptJobMaterializesRemoteConsolePlan(t *testing.T) {
	provider, server, payloads := validationTestProvider(t)
	specification := validRemoteSpecification(t, server.URL, payloads)

	job, err := provider.AdaptJob(specification)
	if err != nil {
		t.Fatalf("AdaptJob() error = %v", err)
	}
	if job.ID != "remote-paper-job" || job.Provider != ProviderName || job.MaxOutputBytes != 1<<20 || job.Timeout() != time.Minute || job.PreparationTimeout() != 2*time.Minute || job.GracefulShutdownTimeout() != 30*time.Second || !job.UsesPhaseTimeouts() {
		t.Fatalf("adapted job = %#v", job)
	}
	var config configuration
	if err := json.Unmarshal(job.Environment, &config); err != nil {
		t.Fatalf("decode adapted environment: %v", err)
	}
	if config.Target.SizeBytes != int64(len(payloads["/target"])) || len(config.Dependencies) != 1 {
		t.Fatalf("adapted downloads = %#v / %#v", config.Target, config.Dependencies)
	}
	if len(config.TestPlan.Console) != 1 || config.TestPlan.Console[0].Command != "provenance-success" || config.TestPlan.Console[0].Assertions[0].Operator != "contains" {
		t.Fatalf("adapted console plan = %#v", config.TestPlan)
	}

	environment, err := provider.Resolve(context.Background(), execution.Request{JobID: job.ID, Environment: job.Environment, Limits: execution.Limits{MaxOutputBytes: job.MaxOutputBytes}})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	prepared, err := environment.Prepare(context.Background())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	planPath := filepath.Join(prepared.(*preparedEnvironment).workspace.Root(), "server", "provenance-test-plan.json")
	plan, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("read materialized test plan: %v", err)
	}
	for _, expected := range []string{`"console"`, `"id": "command-success"`, `"operator": "contains"`} {
		if !strings.Contains(string(plan), expected) {
			t.Errorf("materialized plan does not contain %q: %s", expected, plan)
		}
	}
	if err := prepared.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
}

func TestAdaptJobRejectsMissingSizesAndConfiguredQuotaOverruns(t *testing.T) {
	provider, server, payloads := validationTestProvider(t)

	for name, test := range map[string]struct {
		mutate func(*runnerv1.JobSpecification)
		want   string
	}{
		"zero target size": {
			mutate: func(specification *runnerv1.JobSpecification) { specification.Artifact.SizeBytes = 0 },
			want:   "artifact.size_bytes must be positive",
		},
		"zero dependency size": {
			mutate: func(specification *runnerv1.JobSpecification) { specification.Dependencies[0].Object.SizeBytes = 0 },
			want:   "dependencies[0].object.size_bytes must be positive",
		},
		"per artifact quota": {
			mutate: func(specification *runnerv1.JobSpecification) {
				provider.config.MaximumArtifactBytes = int64(len(payloads["/target"]) - 1)
			},
			want: "artifact.size_bytes exceeds the configured",
		},
		"dependency quota": {
			mutate: func(specification *runnerv1.JobSpecification) {
				provider.config.MaximumDependencyBytes = int64(len(payloads["/dependency"]) - 1)
			},
			want: "dependency artifacts exceed the aggregate",
		},
	} {
		t.Run(name, func(t *testing.T) {
			originalArtifactQuota := provider.config.MaximumArtifactBytes
			originalDependencyQuota := provider.config.MaximumDependencyBytes
			t.Cleanup(func() {
				provider.config.MaximumArtifactBytes = originalArtifactQuota
				provider.config.MaximumDependencyBytes = originalDependencyQuota
			})
			specification := validRemoteSpecification(t, server.URL, payloads)
			test.mutate(specification)
			if _, err := provider.AdaptJob(specification); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("AdaptJob() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAdaptedDownloadFailsClosedOnActualByteCountMismatch(t *testing.T) {
	provider, server, payloads := validationTestProvider(t)
	specification := validRemoteSpecification(t, server.URL, payloads)
	specification.Artifact.SizeBytes++

	job, err := provider.AdaptJob(specification)
	if err != nil {
		t.Fatalf("AdaptJob() error = %v", err)
	}
	environment, err := provider.Resolve(context.Background(), execution.Request{JobID: job.ID, Environment: job.Environment, Limits: execution.Limits{MaxOutputBytes: job.MaxOutputBytes}})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	prepared, err := environment.Prepare(context.Background())
	if !errors.Is(err, artifact.ErrSizeMismatch) || prepared != nil {
		t.Fatalf("Prepare() = %#v, %v; want exact-size failure", prepared, err)
	}
}

func TestAdaptJobRejectsDigestAndPolicyMismatches(t *testing.T) {
	provider, server, payloads := validationTestProvider(t)
	for name, test := range map[string]struct {
		mutate func(*runnerv1.JobSpecification)
		want   string
	}{
		"configuration digest": {
			mutate: func(specification *runnerv1.JobSpecification) {
				specification.NormalizedConfigurationJson = append(specification.NormalizedConfigurationJson, ' ')
			},
			want: "hashes.configuration does not match",
		},
		"artifact digest": {
			mutate: func(specification *runnerv1.JobSpecification) {
				specification.Hashes.Artifact = protoDigest([]byte("other"))
			},
			want: "hashes.artifact does not match",
		},
		"network": {
			mutate: func(specification *runnerv1.JobSpecification) {
				specification.EffectivePolicy.Network.Mode = runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST
			},
			want: "network.mode must be none",
		},
		"missing preparation timeout": {
			mutate: func(specification *runnerv1.JobSpecification) {
				specification.EffectivePolicy.PreparationTimeout = nil
			},
			want: "effective_policy.preparation_timeout is required",
		},
		"missing graceful shutdown timeout": {
			mutate: func(specification *runnerv1.JobSpecification) {
				specification.EffectivePolicy.GracefulShutdownTimeout = nil
			},
			want: "effective_policy.graceful_shutdown_timeout is required",
		},
	} {
		t.Run(name, func(t *testing.T) {
			specification := validRemoteSpecification(t, server.URL, payloads)
			test.mutate(specification)
			if _, err := provider.AdaptJob(specification); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("AdaptJob() error = %v, want %q", err, test.want)
			}
		})
	}
}

func validRemoteSpecification(t *testing.T, baseURL string, payloads map[string][]byte) *runnerv1.JobSpecification {
	t.Helper()
	normalized, err := json.Marshal(map[string]any{
		"apiVersion": "provenance.dev/v1",
		"project":    map[string]any{"id": "success-fixture", "name": "SuccessFixture"},
		"artifact":   map[string]any{"id": "success-fixture", "path": "build/libs/success.jar", "version": "1.0.0"},
		"dependencies": []map[string]any{{
			"id": "dependencyfixture", "provider": "organization-upload", "artifactId": "dependency", "version": "1.0.0", "sha256": artifact.SHA256(payloads["/dependency"]).String(), "required": true,
		}},
		"tests": map[string]any{
			"startup": map[string]any{"timeoutSeconds": 120, "stabilizationSeconds": 10, "requirePluginEnabled": true, "shutdownTimeoutSeconds": 30, "requireCleanShutdown": true},
			"console": []map[string]any{{
				"id": "command-success", "command": "provenance-success", "timeoutSeconds": 10,
				"assertions": []map[string]any{{"stream": "combined", "operator": "contains", "pattern": "FIXTURE_COMMAND_OK", "match": "present", "minimumOccurrences": 1}},
			}},
		},
		"resources": map[string]any{"cpuCores": 1.5, "memoryMiB": 1024, "diskMiB": 2048, "processes": 64, "wallTimeoutSeconds": 60, "logBytes": 1 << 20},
	})
	if err != nil {
		t.Fatal(err)
	}
	targetDigest := protoDigest(payloads["/target"])
	dependencyDigest := protoDigest(payloads["/dependency"])
	return &runnerv1.JobSpecification{
		Lease:   &runnerv1.LeaseIdentity{LeaseId: "lease", JobId: "remote-paper-job", ExecutionId: "execution"},
		Attempt: &runnerv1.AttemptIdentity{AttemptId: "attempt", AttemptNumber: 1, ReleaseCandidateId: "candidate", MatrixEntryId: "paper"},
		Hashes: &runnerv1.JobHashes{
			Artifact:      targetDigest,
			Configuration: protoDigest(normalized),
			Dependencies:  []*runnerv1.DependencyDigest{{DependencyId: "dependencyfixture", Filename: "dependency.jar", Digest: dependencyDigest}},
		},
		Environment: &runnerv1.ResolvedEnvironment{
			Provider: runnerv1.ServerProvider_SERVER_PROVIDER_PAPER, GameVersion: "1.21.8", ServerBuild: 60,
			JavaDistribution: "eclipse-temurin", JavaVersion: "21.0.8+9", OperatingSystem: runnerv1.OperatingSystem_OPERATING_SYSTEM_LINUX, Architecture: runnerv1.Architecture_ARCHITECTURE_AMD64,
		},
		EffectivePolicy: &runnerv1.EffectivePolicy{
			Sandbox:                 runnerv1.SandboxKind_SANDBOX_KIND_GVISOR,
			Network:                 &runnerv1.NetworkPolicy{Mode: runnerv1.NetworkMode_NETWORK_MODE_NONE},
			Resources:               &runnerv1.ResourceLimits{CpuMillis: 1500, MemoryBytes: 1 << 30, DiskBytes: 2 << 30, ProcessCount: 64},
			PreparationTimeout:      durationpb.New(2 * time.Minute),
			ExecutionTimeout:        durationpb.New(time.Minute),
			GracefulShutdownTimeout: durationpb.New(30 * time.Second),
		},
		Artifact:                    &runnerv1.ObjectDownload{Uri: baseURL + "/target", Digest: targetDigest, Filename: "success.jar", SizeBytes: int64(len(payloads["/target"]))},
		Dependencies:                []*runnerv1.DependencyInput{{DependencyId: "dependencyfixture", Object: &runnerv1.ObjectDownload{Uri: baseURL + "/dependency", Digest: dependencyDigest, Filename: "dependency.jar", SizeBytes: int64(len(payloads["/dependency"]))}}},
		NormalizedConfigurationJson: normalized,
	}
}

func protoDigest(payload []byte) *runnerv1.Digest {
	digest := artifact.SHA256(payload)
	return &runnerv1.Digest{Algorithm: runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}
}
