package gatewayclient

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestValidateOfferAcceptsBoundedPaperOfferWithoutMutation(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validOfferConfig(), nil)
	offer := validLeaseOffer(now)
	original := proto.Clone(offer)

	if rejection := client.validateOffer(offer, now, 10*time.Minute); rejection != nil {
		t.Fatalf("validateOffer() rejection = %#v", rejection)
	}
	if !proto.Equal(offer, original) {
		t.Fatal("validateOffer() mutated the offer")
	}
}

func TestValidateOfferReturnsStableBoundedRejections(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	config := validOfferConfig()
	tests := []struct {
		name   string
		mutate func(*runnerv1.LeaseOffer)
		code   string
		reason runnerv1.LeaseRejectionReason
	}{
		{name: "missing job", mutate: func(value *runnerv1.LeaseOffer) { value.Job = nil }, code: "invalid_offer", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "expired offer", mutate: func(value *runnerv1.LeaseOffer) { value.OfferExpiresAt = timestamppb.New(now) }, code: "offer_expired", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_OFFER_EXPIRED},
		{name: "offer beyond window", mutate: func(value *runnerv1.LeaseOffer) { value.OfferExpiresAt = timestamppb.New(now.Add(11 * time.Minute)) }, code: "invalid_offer_expiration", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "lease before offer", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Lease.ExpiresAt = value.OfferExpiresAt }, code: "invalid_lease_expiration", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "missing lease identity", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Lease.LeaseId = "" }, code: "invalid_identity", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "non UUID job identity", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Lease.JobId = "job-1" }, code: "invalid_identity", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "job execution mismatch", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Lease.ExecutionId = "20000000-0000-0000-0000-000000000002" }, code: "invalid_identity", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "invalid attempt number", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Attempt.AttemptNumber = 0 }, code: "invalid_identity", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "scope mismatch", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.OrganizationScope = organizationScope("40000000-0000-0000-0000-000000000002")
		}, code: "scope_mismatch", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_POLICY},
		{name: "missing policy hash", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Hashes.Policy = nil }, code: "invalid_hashes", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "configuration hash mismatch", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.NormalizedConfigurationJson = []byte(`{"schemaVersion":2}`)
		}, code: "configuration_hash_mismatch", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "configuration trailing JSON", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.NormalizedConfigurationJson = []byte(`{} {}`)
			value.Job.Hashes.Configuration = offerDigest(value.Job.NormalizedConfigurationJson)
		}, code: "invalid_configuration", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "unsupported operating system", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.Environment.OperatingSystem = runnerv1.OperatingSystem_OPERATING_SYSTEM_WINDOWS
		}, code: "unsupported_environment", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "missing catalog pin", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Environment.CatalogSnapshotId = "" }, code: "invalid_environment", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "missing target plugin name", mutate: func(value *runnerv1.LeaseOffer) { value.Job.TargetPluginName = "" }, code: "invalid_target_plugin_name", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "target plugin starts with dot", mutate: func(value *runnerv1.LeaseOffer) { value.Job.TargetPluginName = ".plugin" }, code: "invalid_target_plugin_name", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "target plugin starts with hyphen", mutate: func(value *runnerv1.LeaseOffer) { value.Job.TargetPluginName = "-plugin" }, code: "invalid_target_plugin_name", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "reserved target plugin name", mutate: func(value *runnerv1.LeaseOffer) { value.Job.TargetPluginName = "Paper" }, code: "invalid_target_plugin_name", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "missing dependency plugin name", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Dependencies[0].PluginName = "" }, code: "invalid_dependency_plugin_name", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "dependency plugin starts with dot", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Dependencies[0].PluginName = ".plugin" }, code: "invalid_dependency_plugin_name", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "dependency plugin starts with hyphen", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Dependencies[0].PluginName = "-plugin" }, code: "invalid_dependency_plugin_name", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "duplicate dependency plugin name", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Dependencies[0].PluginName = value.Job.TargetPluginName }, code: "duplicate_plugin_name", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "unsupported network", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.EffectivePolicy.Network.Mode = runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST
		}, code: "unsupported_network", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_POLICY},
		{name: "resource over capacity", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.EffectivePolicy.Resources.CpuMillis = config.Resources.CPUMillis + 1
		}, code: "resources_exceed_capacity", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_POLICY},
		{name: "unknown requirement", mutate: func(value *runnerv1.LeaseOffer) { value.Job.EffectivePolicy.Requirement = 99 }, code: "invalid_requirement", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_POLICY},
		{name: "missing dependency download", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Dependencies = nil }, code: "dependency_mismatch", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "dependency order mismatch", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Dependencies[0].DependencyId = "other" }, code: "dependency_mismatch", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "artifact hash mismatch", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Artifact.Digest = offerDigest([]byte("different")) }, code: "artifact_hash_mismatch", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "insecure download", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Artifact.Uri = "http://objects.example/plugin.jar" }, code: "invalid_download", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "literal IP download", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Artifact.Uri = "https://127.0.0.1/plugin.jar" }, code: "invalid_download", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "non TLS port download", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Artifact.Uri = "https://objects.example:8443/plugin.jar" }, code: "invalid_download", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "artifact exceeds disk", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.Artifact.SizeBytes = int64(value.Job.EffectivePolicy.Resources.DiskBytes) + 1
		}, code: "downloads_exceed_disk", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_POLICY},
		{name: "aggregate exceeds disk", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.Artifact.SizeBytes = int64(value.Job.EffectivePolicy.Resources.DiskBytes) - 1
			value.Job.Dependencies[0].Object.SizeBytes = 2
		}, code: "downloads_exceed_disk", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_POLICY},
		{name: "filename collision", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.Dependencies[0].Object.Filename = value.Job.Artifact.Filename
			value.Job.Hashes.Dependencies[0].Filename = value.Job.Artifact.Filename
		}, code: "duplicate_filename", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "download expires at lease", mutate: func(value *runnerv1.LeaseOffer) { value.Job.Artifact.ExpiresAt = value.Job.Lease.ExpiresAt }, code: "download_expired", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "malformed complete log upload", mutate: func(value *runnerv1.LeaseOffer) { value.Job.CompleteLogUpload = &runnerv1.ObjectUpload{} }, code: "invalid_complete_log_upload", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "insecure complete log upload", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.CompleteLogUpload = validCompleteLogUpload(now)
			value.Job.CompleteLogUpload.Uri = "http://logs.example/log.gz?signature=secret"
		}, code: "invalid_complete_log_upload", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "literal IP complete log upload", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.CompleteLogUpload = validCompleteLogUpload(now)
			value.Job.CompleteLogUpload.Uri = "https://127.0.0.1/log.gz?signature=secret"
		}, code: "invalid_complete_log_upload", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
		{name: "expired complete log upload", mutate: func(value *runnerv1.LeaseOffer) {
			value.Job.CompleteLogUpload = validCompleteLogUpload(now)
			value.Job.CompleteLogUpload.ExpiresAt = value.Job.Lease.ExpiresAt
		}, code: "invalid_complete_log_upload", reason: runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			offer := validLeaseOffer(now)
			test.mutate(offer)
			first := validateOffer(offer, config, now, 10*time.Minute)
			second := validateOffer(offer, config, now, 10*time.Minute)
			if first == nil || second == nil {
				t.Fatalf("validateOffer() = %#v / %#v", first, second)
			}
			if first.Code != test.code || first.Reason != test.reason {
				t.Fatalf("rejection = %#v, want code %q reason %v", first, test.code, test.reason)
			}
			if *first != *second {
				t.Fatalf("rejection is unstable: %#v / %#v", first, second)
			}
			if len(first.Code) > maximumIdentifierBytes || len(first.Message) > maximumOfferDetailBytes {
				t.Fatalf("rejection is unbounded: %#v", first)
			}
		})
	}
}

func TestValidateOfferAcceptsBoundedCompleteLogUploadWithoutMutation(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	offer := validLeaseOffer(now)
	offer.Job.CompleteLogUpload = validCompleteLogUpload(now)
	original := proto.Clone(offer)
	if rejection := validateOffer(offer, validOfferConfig(), now, 10*time.Minute); rejection != nil {
		t.Fatalf("validateOffer() rejection = %#v", rejection)
	}
	if !proto.Equal(offer, original) {
		t.Fatal("validateOffer() mutated the upload capability")
	}
}

func validCompleteLogUpload(now time.Time) *runnerv1.ObjectUpload {
	return &runnerv1.ObjectUpload{
		Uri:         "https://logs.example/staging/execution/attempt/log.gz?signature=secret",
		ContentType: completeLogUploadContentType,
		ExpiresAt:   timestamppb.New(now.Add(9 * time.Minute)),
	}
}

func TestValidateOfferBoundsMessageAndDependenciesBeforeAllocation(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	config := validOfferConfig()

	oversized := validLeaseOffer(now)
	oversized.Job.NormalizedConfigurationJson = make([]byte, MaximumMessageBytes+1)
	if rejection := validateOffer(oversized, config, now, 10*time.Minute); rejection == nil || rejection.Code != "offer_too_large" {
		t.Fatalf("oversized rejection = %#v", rejection)
	}

	tooMany := validLeaseOffer(now)
	tooMany.Job.Hashes.Dependencies = make([]*runnerv1.DependencyDigest, maximumOfferDependencies+1)
	if rejection := validateOffer(tooMany, config, now, 10*time.Minute); rejection == nil || rejection.Code != "too_many_dependencies" {
		t.Fatalf("dependency bound rejection = %#v", rejection)
	}

	boundary := validLeaseOffer(now)
	boundary.Job.Hashes.Dependencies = nil
	boundary.Job.Dependencies = nil
	for index := range maximumOfferDependencies {
		id := fmt.Sprintf("dependency-%03d", index)
		filename := fmt.Sprintf("dependency-%03d.jar", index)
		digest := offerDigest([]byte(id))
		boundary.Job.Hashes.Dependencies = append(boundary.Job.Hashes.Dependencies, &runnerv1.DependencyDigest{DependencyId: id, Filename: filename, Digest: digest})
		boundary.Job.Dependencies = append(boundary.Job.Dependencies, &runnerv1.DependencyInput{
			DependencyId: id,
			PluginName:   fmt.Sprintf("Dependency%03d", index),
			Object: &runnerv1.ObjectDownload{
				Uri:       "https://objects.example/" + filename,
				Digest:    digest,
				Filename:  filename,
				ExpiresAt: timestamppb.New(now.Add(9 * time.Minute)),
				SizeBytes: 1,
			},
		})
	}
	if rejection := validateOffer(boundary, config, now, 10*time.Minute); rejection != nil {
		t.Fatalf("dependency boundary rejected: %#v", rejection)
	}
}

func TestValidateOfferEnforcesExactOrganizationScope(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	config := validOfferConfig()
	config.ExpectedScope = ExpectedScope{Kind: ScopeOrganization, OrganizationID: "40000000-0000-0000-0000-000000000001"}
	offer := validLeaseOffer(now)
	offer.Job.OrganizationScope = organizationScope(config.ExpectedScope.OrganizationID)
	if rejection := validateOffer(offer, config, now, 10*time.Minute); rejection != nil {
		t.Fatalf("matching organization rejected: %#v", rejection)
	}
	offer.Job.OrganizationScope = platformScope()
	if rejection := validateOffer(offer, config, now, 10*time.Minute); rejection == nil || rejection.Code != "scope_mismatch" {
		t.Fatalf("platform scope rejection = %#v", rejection)
	}
}

func validOfferConfig() Config {
	return Config{
		ExpectedScope: ExpectedScope{Kind: ScopePlatform},
		Resources: Resources{
			CPUMillis:    2_000,
			MemoryBytes:  2 << 30,
			DiskBytes:    4 << 30,
			ProcessCount: 128,
		},
	}
}

func validLeaseOffer(now time.Time) *runnerv1.LeaseOffer {
	configuration := []byte(`{"schemaVersion":1}`)
	artifactDigest := offerDigest([]byte("plugin"))
	dependencyDigest := offerDigest([]byte("dependency"))
	downloadExpiration := timestamppb.New(now.Add(9 * time.Minute))
	return &runnerv1.LeaseOffer{
		OfferExpiresAt: timestamppb.New(now.Add(time.Minute)),
		Job: &runnerv1.JobSpecification{
			TargetPluginName: "TargetPlugin",
			Lease: &runnerv1.LeaseIdentity{
				LeaseId:     "10000000-0000-0000-0000-000000000001",
				JobId:       "20000000-0000-0000-0000-000000000001",
				ExecutionId: "20000000-0000-0000-0000-000000000001",
				ExpiresAt:   timestamppb.New(now.Add(8 * time.Minute)),
			},
			Attempt: &runnerv1.AttemptIdentity{
				AttemptId:          "30000000-0000-0000-0000-000000000001",
				AttemptNumber:      1,
				ReleaseCandidateId: "40000000-0000-0000-0000-000000000001",
				MatrixEntryId:      "50000000-0000-0000-0000-000000000001",
			},
			OrganizationScope: platformScope(),
			Hashes: &runnerv1.JobHashes{
				Artifact:      artifactDigest,
				Configuration: offerDigest(configuration),
				Dependencies: []*runnerv1.DependencyDigest{{
					DependencyId: "dependency-1",
					Filename:     "dependency.jar",
					Digest:       dependencyDigest,
				}},
				Environment: offerDigest([]byte("environment")),
				Policy:      offerDigest([]byte("policy")),
			},
			Environment: &runnerv1.ResolvedEnvironment{
				Provider:          runnerv1.ServerProvider_SERVER_PROVIDER_PAPER,
				GameVersion:       "1.21.8",
				ServerVersion:     "1.21.8",
				ServerBuild:       60,
				JavaDistribution:  "eclipse-temurin",
				JavaVersion:       "21.0.8+9",
				OperatingSystem:   runnerv1.OperatingSystem_OPERATING_SYSTEM_LINUX,
				Architecture:      runnerv1.Architecture_ARCHITECTURE_AMD64,
				RunnerImage:       offerDigest([]byte("runner-image")),
				ServerBinary:      offerDigest([]byte("server-binary")),
				CatalogSnapshotId: "60000000-0000-0000-0000-000000000001",
			},
			EffectivePolicy: &runnerv1.EffectivePolicy{
				Sandbox:                 runnerv1.SandboxKind_SANDBOX_KIND_GVISOR,
				Network:                 &runnerv1.NetworkPolicy{Mode: runnerv1.NetworkMode_NETWORK_MODE_NONE},
				Resources:               &runnerv1.ResourceLimits{CpuMillis: 1_500, MemoryBytes: 1 << 30, DiskBytes: 2 << 30, ProcessCount: 64},
				PreparationTimeout:      durationpb.New(2 * time.Minute),
				ExecutionTimeout:        durationpb.New(time.Minute),
				GracefulShutdownTimeout: durationpb.New(30 * time.Second),
				Requirement:             runnerv1.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED,
			},
			Artifact: &runnerv1.ObjectDownload{
				Uri:       "https://objects.example/plugin.jar",
				Digest:    artifactDigest,
				Filename:  "plugin.jar",
				ExpiresAt: downloadExpiration,
				SizeBytes: 6,
			},
			Dependencies: []*runnerv1.DependencyInput{{
				DependencyId: "dependency-1",
				PluginName:   "DependencyPlugin",
				Object: &runnerv1.ObjectDownload{
					Uri:       "https://objects.example/dependency.jar",
					Digest:    dependencyDigest,
					Filename:  "dependency.jar",
					ExpiresAt: downloadExpiration,
					SizeBytes: 10,
				},
			}},
			NormalizedConfigurationJson: configuration,
		},
	}
}

func offerDigest(value []byte) *runnerv1.Digest {
	digest := sha256.Sum256(value)
	return &runnerv1.Digest{Algorithm: runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}
}
