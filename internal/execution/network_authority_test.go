package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func executionAuthority(t *testing.T, lifetime time.Duration) (*p.JobSpecification, *networkpolicy.AuthorityRoute) {
	t.Helper()
	now := time.Now()
	policy := &p.EffectivePolicy{Sandbox: p.SandboxKind_SANDBOX_KIND_GVISOR, Requirement: p.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED,
		Resources: &p.ResourceLimits{CpuMillis: 2000, MemoryBytes: 2 << 30, DiskBytes: 4 << 30, ProcessCount: 256}, PreparationTimeout: durationpb.New(time.Minute), ExecutionTimeout: durationpb.New(time.Minute), GracefulShutdownTimeout: durationpb.New(10 * time.Second),
		NetworkV2: &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_ALLOWLIST, MaximumConnections: 16, MaximumBytesPerSecond: 65536, Permissions: []*p.NetworkPermissionV2{{Hostname: "fixture.example.com", Port: 8080, Transport: p.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP}}}}
	digest, err := networkpolicy.EffectivePolicyV2SHA256(policy)
	if err != nil {
		t.Fatal(err)
	}
	job := &p.JobSpecification{Lease: &p.LeaseIdentity{JobId: "10000000-0000-4000-8000-000000000001", LeaseId: "20000000-0000-4000-8000-000000000001", ExecutionId: "30000000-0000-4000-8000-000000000001", ExpiresAt: timestamppb.New(now.Add(2 * time.Minute))},
		Attempt: &p.AttemptIdentity{AttemptId: "40000000-0000-4000-8000-000000000001", ReleaseCandidateId: "50000000-0000-4000-8000-000000000001", MatrixEntryId: "60000000-0000-4000-8000-000000000001", AttemptNumber: 1}, EffectivePolicy: policy, Hashes: &p.JobHashes{Policy: &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}}}
	guard, err := networkpolicy.NewAuthorityRoute(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := guard.Close(); err != nil {
			t.Error(err)
		}
	})
	receipt := &p.LeaseReconciliation{Lease: job.Lease, Attempt: job.Attempt, Status: p.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: p.JobPhase_JOB_PHASE_RUNNING, Disposition: p.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE,
		NetworkAuthorityV2: &p.NetworkAuthorityV2{Policy: job.Hashes.Policy, State: p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT, CheckedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(lifetime))}}
	if err := guard.Reconcile(context.Background(), receipt, []p.ProtocolFeature{1, 3, 9, 10}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	return job, guard
}

func TestNetworkAuthoritySupervisorRefusesAbsentChangedOrWithdrawnGuard(t *testing.T) {
	for _, kind := range []string{"absent", "changed job", "changed policy", "withdrawn"} {
		t.Run(kind, func(t *testing.T) {
			job, guard := executionAuthority(t, 30*time.Second)
			switch kind {
			case "absent":
				guard = nil
			case "changed job":
				job.Attempt.AttemptNumber++
			case "changed policy":
				job.EffectivePolicy.NetworkV2.MaximumConnections++
			case "withdrawn":
				_ = guard.Withdraw()
			}
			result := SuperviseNetworkAuthority(context.Background(), job, guard, func(context.Context) Result { t.Fatal("unowned worker invoked"); return Result{} })
			if result.Classification != ClassificationInfrastructureFailure || result.Failure.Code != "network_authority_lost" || result.Phase != PhasePreparation || result.Execution != nil || result.Cleanup != nil {
				t.Fatal("early failure invented execution or cleanup", result)
			}
		})
	}
}

func TestNetworkAuthoritySupervisorWaitsForNormalWorkerCleanup(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		lifetime := 30 * time.Second
		if expiry {
			lifetime = 150 * time.Millisecond
		}
		job, guard := executionAuthority(t, lifetime)
		entered, stopped, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		result := make(chan Result, 1)
		go func() {
			result <- SuperviseNetworkAuthority(context.Background(), job, guard, func(ctx context.Context) Result {
				if NetworkAuthorityRoute(ctx) != guard {
					t.Error("owned guard not injected")
				}
				close(entered)
				<-ctx.Done()
				if !errors.Is(context.Cause(ctx), ErrNetworkAuthorityLost) {
					t.Error("withdrawal became generic cancellation")
				}
				close(stopped)
				<-release
				return Result{Status: "failed", Classification: ClassificationCancelled, Cleanup: &CleanupResult{Attempted: true, Succeeded: true}}
			})
		}()
		<-entered
		if !expiry {
			if err := guard.Withdraw(); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			t.Fatal("worker stop required gateway polling")
		}
		select {
		case <-result:
			t.Fatal("withdrawal claimed worker cleanup before return")
		default:
		}
		close(release)
		got := <-result
		if got.Classification != ClassificationInfrastructureFailure || got.Failure.Code != "network_authority_lost" || got.Cleanup == nil || !got.Cleanup.Succeeded {
			t.Fatal("wrong authority-loss classification", got)
		}
	}
}

func TestNetworkAuthoritySupervisorPreservesSuccessAndCleanupFailure(t *testing.T) {
	for _, cleanupFailed := range []bool{false, true} {
		job, guard := executionAuthority(t, 30*time.Second)
		got := SuperviseNetworkAuthority(context.Background(), job, guard, func(ctx context.Context) Result {
			if cleanupFailed {
				_ = guard.Withdraw()
				return Result{Status: "failed", Classification: ClassificationInfrastructureFailure, Phase: PhaseCleanup, Failure: NewFailure(ClassificationInfrastructureFailure, "original_cleanup_failed", "original cleanup failure"), Cleanup: &CleanupResult{Attempted: true, Succeeded: false}}
			}
			return Result{Status: "passed", Classification: ClassificationPassed, Cleanup: &CleanupResult{Attempted: true, Succeeded: true}}
		})
		if cleanupFailed {
			if got.Failure.Code != "original_cleanup_failed" || got.Cleanup.Succeeded {
				t.Fatal("cleanup failure masked", got)
			}
		} else if got.Classification != ClassificationPassed {
			t.Fatal("own teardown changed successful result", got)
		}
		select {
		case <-guard.Done():
		default:
			t.Fatal("completed guard left live")
		}
	}
}

func TestNetworkAuthorityCleanupFailureCannotClaimCapacity(t *testing.T) {
	result := Result{Status: "passed", Classification: ClassificationPassed, Cleanup: &CleanupResult{Attempted: true, Succeeded: true}}
	applyNetworkCleanup(&result, networkpolicy.ErrActuation)
	if result.Status != "failed" || result.Classification != ClassificationInfrastructureFailure || result.Phase != PhaseCleanup || result.Cleanup == nil || result.Cleanup.Succeeded || result.Failure.Code != "network_cleanup_failed" {
		t.Fatal("route cleanup failure lost", result)
	}
}
