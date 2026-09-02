package gatewayclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	"github.com/bwmp-dev/provenance-runner/internal/pluginname"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maximumOfferDependencies = 128
	maximumAttemptNumber     = 1_000_000
	maximumDownloadURIBytes  = 4096
	maximumFilenameBytes     = 255
	maximumOfferDetailBytes  = 256
)

type OfferRejection struct {
	Reason  runnerv1.LeaseRejectionReason
	Code    string
	Message string
}

func (r *OfferRejection) Error() string {
	if r == nil {
		return ""
	}
	return r.Code + ": " + r.Message
}

// validateOffer keeps hostile job validation separate from state transitions so
// no offer is persisted or acknowledged before every bounded check succeeds.
func (c *Client) validateOffer(offer *runnerv1.LeaseOffer, now time.Time, leaseDuration time.Duration, jobCorrelationV1 bool) *OfferRejection {
	if c == nil {
		return rejectUnsupported("invalid_offer", "lease offer cannot be validated")
	}
	return validateOffer(offer, c.config, now, leaseDuration, jobCorrelationV1)
}

func validateOffer(offer *runnerv1.LeaseOffer, config Config, now time.Time, leaseDuration time.Duration, jobCorrelationV1 bool) *OfferRejection {
	if offer == nil || offer.GetJob() == nil {
		return rejectUnsupported("invalid_offer", "lease offer job is required")
	}
	if len(offer.GetJob().GetNormalizedConfigurationJson()) > MaximumMessageBytes {
		return rejectUnsupported("offer_too_large", "lease offer exceeds the message size limit")
	}
	if len(offer.GetJob().GetDependencies()) > maximumOfferDependencies || len(offer.GetJob().GetHashes().GetDependencies()) > maximumOfferDependencies {
		return rejectUnsupported("too_many_dependencies", "job dependency count exceeds the supported limit")
	}
	if proto.Size(offer) > MaximumMessageBytes {
		return rejectUnsupported("offer_too_large", "lease offer exceeds the message size limit")
	}
	if leaseDuration < minimumLeaseDuration || leaseDuration > maximumLeaseDuration {
		return rejectUnsupported("invalid_lease_duration", "negotiated lease duration is invalid")
	}
	now = now.UTC()
	offerExpiresAt, rejection := offerExpiration(offer.GetOfferExpiresAt(), now, leaseDuration)
	if rejection != nil {
		return rejection
	}
	job := offer.GetJob()
	leaseExpiresAt, rejection := validateOfferIdentity(job, now, offerExpiresAt, leaseDuration)
	if rejection != nil {
		return rejection
	}
	if rejection := validateOfferScope(job.GetOrganizationScope(), config.ExpectedScope); rejection != nil {
		return rejection
	}
	if rejection := validateOfferJobCorrelation(job, config.ExpectedScope, jobCorrelationV1); rejection != nil {
		return rejection
	}
	if rejection := validateOfferHashes(job.GetHashes()); rejection != nil {
		return rejection
	}
	if rejection := validateOfferConfiguration(job.GetNormalizedConfigurationJson(), job.GetHashes().GetConfiguration()); rejection != nil {
		return rejection
	}
	if rejection := validateOfferEnvironment(job.GetEnvironment()); rejection != nil {
		return rejection
	}
	if rejection := validateOfferPluginNames(job); rejection != nil {
		return rejection
	}
	if rejection := validateOfferPolicy(job.GetEffectivePolicy(), config.Resources); rejection != nil {
		return rejection
	}
	if rejection := validateOfferDownloads(job, offerExpiresAt, leaseExpiresAt); rejection != nil {
		return rejection
	}
	if _, rejection := validateCompleteLogUpload(job.GetCompleteLogUpload(), now, offerExpiresAt, leaseExpiresAt); rejection != nil {
		return rejection
	}
	return nil
}

func validateOfferPluginNames(job *runnerv1.JobSpecification) *OfferRejection {
	if !pluginname.ValidPaper(job.GetTargetPluginName()) {
		return rejectUnsupported("invalid_target_plugin_name", "target plugin name is missing or invalid")
	}
	seen := map[string]struct{}{strings.ToLower(job.GetTargetPluginName()): {}}
	for _, dependency := range job.GetDependencies() {
		if dependency == nil || !pluginname.ValidPaper(dependency.GetPluginName()) {
			return rejectUnsupported("invalid_dependency_plugin_name", "dependency plugin name is missing or invalid")
		}
		key := strings.ToLower(dependency.GetPluginName())
		if _, exists := seen[key]; exists {
			return rejectUnsupported("duplicate_plugin_name", "target and dependency plugin names must be unique")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func offerExpiration(value *timestamppb.Timestamp, now time.Time, leaseDuration time.Duration) (time.Time, *OfferRejection) {
	if err := validateTimestamp("offer.offerExpiresAt", value); err != nil {
		return time.Time{}, rejectUnsupported("invalid_offer_expiration", "offer expiration is missing or invalid")
	}
	expiresAt := value.AsTime()
	if !expiresAt.After(now) {
		return time.Time{}, reject(runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_OFFER_EXPIRED, "offer_expired", "lease offer has expired")
	}
	if expiresAt.After(now.Add(leaseDuration)) {
		return time.Time{}, rejectUnsupported("invalid_offer_expiration", "offer expiration exceeds the negotiated lease window")
	}
	return expiresAt, nil
}

func validateOfferIdentity(job *runnerv1.JobSpecification, now, offerExpiresAt time.Time, leaseDuration time.Duration) (time.Time, *OfferRejection) {
	lease := job.GetLease()
	if lease == nil {
		return time.Time{}, rejectUnsupported("invalid_identity", "lease identity is required")
	}
	for field, value := range map[string]string{
		"leaseId":     lease.GetLeaseId(),
		"jobId":       lease.GetJobId(),
		"executionId": lease.GetExecutionId(),
	} {
		if validateUUID(field, value) != nil {
			return time.Time{}, rejectUnsupported("invalid_identity", "lease identity is invalid")
		}
	}
	if lease.GetJobId() != lease.GetExecutionId() {
		return time.Time{}, rejectUnsupported("invalid_identity", "job and execution identities must match")
	}
	if err := validateTimestamp("lease.expiresAt", lease.GetExpiresAt()); err != nil {
		return time.Time{}, rejectUnsupported("invalid_lease_expiration", "lease expiration is missing or invalid")
	}
	leaseExpiresAt := lease.GetExpiresAt().AsTime()
	if !leaseExpiresAt.After(offerExpiresAt) || leaseExpiresAt.After(now.Add(leaseDuration)) {
		return time.Time{}, rejectUnsupported("invalid_lease_expiration", "lease expiration is outside the negotiated lease window")
	}
	attempt := job.GetAttempt()
	if attempt == nil {
		return time.Time{}, rejectUnsupported("invalid_identity", "attempt identity is required")
	}
	for field, value := range map[string]string{
		"attemptId":          attempt.GetAttemptId(),
		"releaseCandidateId": attempt.GetReleaseCandidateId(),
		"matrixEntryId":      attempt.GetMatrixEntryId(),
	} {
		if validateUUID(field, value) != nil {
			return time.Time{}, rejectUnsupported("invalid_identity", "attempt identity is invalid")
		}
	}
	if attempt.GetAttemptNumber() == 0 || attempt.GetAttemptNumber() > maximumAttemptNumber {
		return time.Time{}, rejectUnsupported("invalid_identity", "attempt number is invalid")
	}
	return leaseExpiresAt, nil
}

func validateOfferScope(scope *runnerv1.OrganizationScope, expected ExpectedScope) *OfferRejection {
	if scope == nil || scope.GetScope() == nil {
		return rejectPolicy("invalid_scope", "job organization scope is required")
	}
	switch expected.Kind {
	case ScopePlatform:
		if scope.GetPlatform() == nil {
			return rejectPolicy("scope_mismatch", "job organization scope does not match the runner")
		}
	case ScopeOrganization:
		if validateUUID("organizationId", scope.GetOrganizationId()) != nil || scope.GetOrganizationId() != expected.OrganizationID {
			return rejectPolicy("scope_mismatch", "job organization scope does not match the runner")
		}
	default:
		return rejectPolicy("invalid_scope", "runner organization scope is invalid")
	}
	return nil
}

func validateOfferHashes(hashes *runnerv1.JobHashes) *OfferRejection {
	if hashes == nil {
		return rejectUnsupported("invalid_hashes", "job hashes are required")
	}
	for _, digest := range []*runnerv1.Digest{hashes.GetArtifact(), hashes.GetConfiguration(), hashes.GetEnvironment(), hashes.GetPolicy()} {
		if !validSHA256(digest) {
			return rejectUnsupported("invalid_hashes", "job hashes must use 32-byte SHA-256 digests")
		}
	}
	if len(hashes.GetDependencies()) > maximumOfferDependencies {
		return rejectUnsupported("too_many_dependencies", "job dependency count exceeds the supported limit")
	}
	seenIDs := make(map[string]struct{}, len(hashes.GetDependencies()))
	seenFilenames := make(map[string]struct{}, len(hashes.GetDependencies()))
	for _, dependency := range hashes.GetDependencies() {
		if dependency == nil || validateIdentifier("dependencyId", dependency.GetDependencyId(), maximumIdentifierBytes) != nil || !validPluginFilename(dependency.GetFilename()) || !validSHA256(dependency.GetDigest()) {
			return rejectUnsupported("invalid_dependency_hash", "job dependency hash entry is invalid")
		}
		if _, exists := seenIDs[dependency.GetDependencyId()]; exists {
			return rejectUnsupported("duplicate_dependency", "job dependency identities must be unique")
		}
		if _, exists := seenFilenames[dependency.GetFilename()]; exists {
			return rejectUnsupported("duplicate_dependency", "job dependency filenames must be unique")
		}
		seenIDs[dependency.GetDependencyId()] = struct{}{}
		seenFilenames[dependency.GetFilename()] = struct{}{}
	}
	return nil
}

func validateOfferConfiguration(configuration []byte, expected *runnerv1.Digest) *OfferRejection {
	if len(configuration) == 0 || len(configuration) > MaximumMessageBytes || !utf8.Valid(configuration) {
		return rejectUnsupported("invalid_configuration", "normalized configuration is missing or invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(configuration))
	var value map[string]json.RawMessage
	if err := decoder.Decode(&value); err != nil || value == nil {
		return rejectUnsupported("invalid_configuration", "normalized configuration must contain one JSON object")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return rejectUnsupported("invalid_configuration", "normalized configuration must contain one JSON object")
	}
	actual := sha256.Sum256(configuration)
	if !validSHA256(expected) || !bytes.Equal(actual[:], expected.GetValue()) {
		return rejectUnsupported("configuration_hash_mismatch", "normalized configuration does not match its declared hash")
	}
	return nil
}

func validateOfferEnvironment(environment *runnerv1.ResolvedEnvironment) *OfferRejection {
	if environment == nil {
		return rejectUnsupported("invalid_environment", "resolved environment is required")
	}
	if environment.GetProvider() != runnerv1.ServerProvider_SERVER_PROVIDER_PAPER ||
		environment.GetOperatingSystem() != runnerv1.OperatingSystem_OPERATING_SYSTEM_LINUX ||
		environment.GetArchitecture() != runnerv1.Architecture_ARCHITECTURE_AMD64 {
		return rejectUnsupported("unsupported_environment", "resolved environment is not supported by this runner")
	}
	for _, value := range []string{environment.GetGameVersion(), environment.GetServerVersion(), environment.GetJavaDistribution(), environment.GetJavaVersion()} {
		if len(value) == 0 || len(value) > maximumIdentifierBytes || !versionPattern.MatchString(value) {
			return rejectUnsupported("invalid_environment", "resolved environment identity is invalid")
		}
	}
	if environment.GetServerVersion() != environment.GetGameVersion() || environment.GetServerBuild() == 0 {
		return rejectUnsupported("invalid_environment", "resolved Paper version and build are invalid")
	}
	if validateUUID("catalogSnapshotId", environment.GetCatalogSnapshotId()) != nil || !validSHA256(environment.GetRunnerImage()) || !validSHA256(environment.GetServerBinary()) {
		return rejectUnsupported("invalid_environment", "resolved environment pins are invalid")
	}
	return nil
}

func validateOfferPolicy(policy *runnerv1.EffectivePolicy, maximum Resources) *OfferRejection {
	if policy == nil || policy.GetResources() == nil {
		return rejectPolicy("invalid_policy", "effective policy and resources are required")
	}
	if policy.GetSandbox() != runnerv1.SandboxKind_SANDBOX_KIND_GVISOR {
		return rejectPolicy("unsupported_sandbox", "effective sandbox is not supported by this runner")
	}
	network := policy.GetNetwork()
	if network == nil || network.GetMode() != runnerv1.NetworkMode_NETWORK_MODE_NONE || len(network.GetAllowlist()) != 0 || network.GetMaximumConnections() != 0 {
		return rejectPolicy("unsupported_network", "effective network policy exceeds this runner's maximum")
	}
	resources := policy.GetResources()
	if resources.GetCpuMillis() == 0 || resources.GetMemoryBytes() == 0 || resources.GetDiskBytes() == 0 || resources.GetProcessCount() == 0 {
		return rejectPolicy("invalid_resources", "effective resource limits must be positive")
	}
	if resources.GetCpuMillis() > maximum.CPUMillis || resources.GetMemoryBytes() > maximum.MemoryBytes || resources.GetDiskBytes() > maximum.DiskBytes || resources.GetProcessCount() > maximum.ProcessCount {
		return rejectPolicy("resources_exceed_capacity", "effective resource limits exceed this runner's capacity")
	}
	for _, duration := range []*durationpb.Duration{policy.GetPreparationTimeout(), policy.GetExecutionTimeout(), policy.GetGracefulShutdownTimeout()} {
		if !validJobDuration(duration) {
			return rejectPolicy("invalid_timeout", "effective policy timeouts are invalid")
		}
	}
	if policy.GetRequirement() != runnerv1.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED && policy.GetRequirement() != runnerv1.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_INFORMATIONAL {
		return rejectPolicy("invalid_requirement", "environment requirement is invalid")
	}
	return nil
}

func validateOfferDownloads(job *runnerv1.JobSpecification, offerExpiresAt, leaseExpiresAt time.Time) *OfferRejection {
	if len(job.GetDependencies()) > maximumOfferDependencies || len(job.GetDependencies()) != len(job.GetHashes().GetDependencies()) {
		return rejectUnsupported("dependency_mismatch", "dependency downloads do not match the ordered dependency hashes")
	}
	maximumBytes := job.GetEffectivePolicy().GetResources().GetDiskBytes()
	if rejection := validateObjectDownload(job.GetArtifact(), offerExpiresAt, leaseExpiresAt, maximumBytes); rejection != nil {
		return rejection
	}
	if !sameDigest(job.GetArtifact().GetDigest(), job.GetHashes().GetArtifact()) {
		return rejectUnsupported("artifact_hash_mismatch", "artifact download does not match the declared artifact hash")
	}
	remainingBytes := maximumBytes - uint64(job.GetArtifact().GetSizeBytes())
	seenFilenames := map[string]struct{}{job.GetArtifact().GetFilename(): {}}
	for index, input := range job.GetDependencies() {
		hash := job.GetHashes().GetDependencies()[index]
		if input == nil || input.GetDependencyId() != hash.GetDependencyId() {
			return rejectUnsupported("dependency_mismatch", "dependency downloads do not match the ordered dependency hashes")
		}
		if rejection := validateObjectDownload(input.GetObject(), offerExpiresAt, leaseExpiresAt, maximumBytes); rejection != nil {
			return rejection
		}
		if input.GetObject().GetFilename() != hash.GetFilename() || !sameDigest(input.GetObject().GetDigest(), hash.GetDigest()) {
			return rejectUnsupported("dependency_hash_mismatch", "dependency download does not match its declared hash")
		}
		if _, exists := seenFilenames[input.GetObject().GetFilename()]; exists {
			return rejectUnsupported("duplicate_filename", "artifact and dependency filenames must be unique")
		}
		seenFilenames[input.GetObject().GetFilename()] = struct{}{}
		size := uint64(input.GetObject().GetSizeBytes())
		if size > remainingBytes {
			return rejectPolicy("downloads_exceed_disk", "declared downloads exceed the effective disk limit")
		}
		remainingBytes -= size
	}
	return nil
}

func validateObjectDownload(object *runnerv1.ObjectDownload, offerExpiresAt, leaseExpiresAt time.Time, maximumBytes uint64) *OfferRejection {
	if object == nil || object.GetSizeBytes() <= 0 || !validSHA256(object.GetDigest()) || !validPluginFilename(object.GetFilename()) {
		return rejectUnsupported("invalid_download", "artifact download metadata is invalid")
	}
	if uint64(object.GetSizeBytes()) > maximumBytes {
		return rejectPolicy("downloads_exceed_disk", "declared downloads exceed the effective disk limit")
	}
	if len(object.GetUri()) == 0 || len(object.GetUri()) > maximumDownloadURIBytes || !utf8.ValidString(object.GetUri()) {
		return rejectUnsupported("invalid_download", "artifact download URI is invalid")
	}
	parsed, err := url.ParseRequestURI(object.GetUri())
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Hostname() == "" || net.ParseIP(parsed.Hostname()) != nil || strings.EqualFold(parsed.Hostname(), "localhost") || (parsed.Port() != "" && parsed.Port() != "443") {
		return rejectUnsupported("invalid_download", "artifact download URI is invalid")
	}
	if err := validateTimestamp("download.expiresAt", object.GetExpiresAt()); err != nil {
		return rejectUnsupported("invalid_download_expiration", "artifact download expiration is missing or invalid")
	}
	expiresAt := object.GetExpiresAt().AsTime()
	if !expiresAt.After(offerExpiresAt) || !expiresAt.After(leaseExpiresAt) {
		return rejectUnsupported("download_expired", "artifact download expires before the initial lease")
	}
	return nil
}

func validJobDuration(value *durationpb.Duration) bool {
	if value == nil || value.CheckValid() != nil {
		return false
	}
	duration := value.AsDuration()
	return duration > 0 && duration <= localjob.MaximumTimeout && duration%time.Millisecond == 0
}

func validPluginFilename(value string) bool {
	return utf8.ValidString(value) && len(value) > 0 && len(value) <= maximumFilenameBytes && strings.TrimSpace(value) == value && value != "." && value != ".." && !strings.ContainsAny(value, "/\\\x00") && strings.HasSuffix(strings.ToLower(value), ".jar")
}

func validSHA256(value *runnerv1.Digest) bool {
	return value != nil && value.GetAlgorithm() == runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 && len(value.GetValue()) == sha256.Size
}

func sameDigest(left, right *runnerv1.Digest) bool {
	return validSHA256(left) && validSHA256(right) && bytes.Equal(left.GetValue(), right.GetValue())
}

func rejectUnsupported(code, message string) *OfferRejection {
	return reject(runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED, code, message)
}

func rejectPolicy(code, message string) *OfferRejection {
	return reject(runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_POLICY, code, message)
}

func reject(reason runnerv1.LeaseRejectionReason, code, message string) *OfferRejection {
	if len(code) == 0 || len(code) > maximumIdentifierBytes || len(message) == 0 || len(message) > maximumOfferDetailBytes {
		panic(fmt.Sprintf("invalid stable offer rejection %q", code))
	}
	return &OfferRejection{Reason: reason, Code: code, Message: message}
}
