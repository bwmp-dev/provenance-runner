package paper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	"github.com/bwmp-dev/provenance-runner/internal/pluginname"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	maximumNormalizedConfigurationBytes = 1 << 20
	maximumProbePlanBytes               = 262_144
	defaultMaximumLineBytes             = 4 << 10
)

var consoleIdentifier = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)

type normalizedConfiguration struct {
	APIVersion   string                    `json:"apiVersion"`
	Project      *normalizedProject        `json:"project"`
	Dependencies []normalizedDependency    `json:"dependencies"`
	Tests        *normalizedTests          `json:"tests"`
	Resources    *normalizedResourceLimits `json:"resources"`
}

type normalizedProject struct {
	Name string `json:"name"`
}

type normalizedDependency struct {
	ID       string `json:"id"`
	Required bool   `json:"required"`
}

type normalizedTests struct {
	Startup *normalizedStartup `json:"startup"`
	Console json.RawMessage    `json:"console"`
}

type normalizedStartup struct {
	StabilizationSeconds int64 `json:"stabilizationSeconds"`
}

type normalizedResourceLimits struct {
	LogBytes int64 `json:"logBytes"`
}

// AdaptJob converts an authoritative remote runner specification into the
// existing bounded local execution request for this exact Paper provider.
func (p *Provider) AdaptJob(specification *runnerv1.JobSpecification) (localjob.Job, error) {
	if p == nil {
		return localjob.Job{}, errors.New("adapt Paper job: provider is nil")
	}
	if specification == nil {
		return localjob.Job{}, errors.New("adapt Paper job: specification is nil")
	}
	if specification.GetLease() == nil || specification.GetLease().GetJobId() == "" {
		return localjob.Job{}, errors.New("adapt Paper job: lease.job_id is required")
	}
	if !pluginname.ValidPaper(specification.GetTargetPluginName()) {
		return localjob.Job{}, errors.New("adapt Paper job: target_plugin_name is missing or invalid")
	}
	if err := p.validateRemoteEnvironment(specification.GetEnvironment()); err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}

	policy := specification.GetEffectivePolicy()
	if policy == nil || policy.GetResources() == nil {
		return localjob.Job{}, errors.New("adapt Paper job: effective_policy.resources is required")
	}
	if policy.GetSandbox() != runnerv1.SandboxKind_SANDBOX_KIND_GVISOR {
		return localjob.Job{}, errors.New("adapt Paper job: effective_policy.sandbox must be gVisor")
	}
	if policy.GetNetwork() == nil || policy.GetNetwork().GetMode() != runnerv1.NetworkMode_NETWORK_MODE_NONE {
		return localjob.Job{}, errors.New("adapt Paper job: effective_policy.network.mode must be none")
	}
	preparationTimeout, err := remoteTimeout("effective_policy.preparation_timeout", policy.GetPreparationTimeout())
	if err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}
	executionTimeout, err := remoteTimeout("effective_policy.execution_timeout", policy.GetExecutionTimeout())
	if err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}
	gracefulShutdownTimeout, err := remoteTimeout("effective_policy.graceful_shutdown_timeout", policy.GetGracefulShutdownTimeout())
	if err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}
	memoryBytes, err := boundedInt64("effective_policy.resources.memory_bytes", policy.GetResources().GetMemoryBytes())
	if err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}
	diskBytes, err := boundedInt64("effective_policy.resources.disk_bytes", policy.GetResources().GetDiskBytes())
	if err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}

	normalized, console, err := decodeNormalizedConfiguration(specification.GetNormalizedConfigurationJson())
	if err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}
	if err := validateConfigurationDigest(specification.GetHashes(), specification.GetNormalizedConfigurationJson()); err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}

	limits := preparationLimits{
		maximumArtifactBytes:    p.config.MaximumArtifactBytes,
		maximumDependencyBytes:  p.config.MaximumDependencyBytes,
		maximumPreparationBytes: p.config.MaximumPreparationBytes,
	}
	target, targetDigest, err := downloadReference("artifact", specification.GetArtifact(), limits.maximumArtifactBytes)
	if err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}
	if err := requireMatchingDigest("hashes.artifact", specification.GetHashes().GetArtifact(), targetDigest); err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}

	configuredDependencies := make(map[string]normalizedDependency, len(normalized.Dependencies))
	for _, dependency := range normalized.Dependencies {
		if dependency.ID == "" {
			return localjob.Job{}, errors.New("adapt Paper job: normalized dependency id is required")
		}
		if _, exists := configuredDependencies[dependency.ID]; exists {
			return localjob.Job{}, fmt.Errorf("adapt Paper job: normalized dependency %q is duplicated", dependency.ID)
		}
		configuredDependencies[dependency.ID] = dependency
	}
	dependencyHashes, err := remoteDependencyHashes(specification.GetHashes())
	if err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}
	dependencies := make([]dependencyReference, 0, len(specification.GetDependencies()))
	requiredDependencies := make([]string, 0, len(specification.GetDependencies()))
	seenDependencies := make(map[string]struct{}, len(specification.GetDependencies()))
	seenPluginNames := map[string]struct{}{strings.ToLower(specification.GetTargetPluginName()): {}}
	for index, input := range specification.GetDependencies() {
		if input == nil || input.GetDependencyId() == "" {
			return localjob.Job{}, fmt.Errorf("adapt Paper job: dependencies[%d].dependency_id is required", index)
		}
		if _, exists := seenDependencies[input.GetDependencyId()]; exists {
			return localjob.Job{}, fmt.Errorf("adapt Paper job: dependency %q is duplicated", input.GetDependencyId())
		}
		seenDependencies[input.GetDependencyId()] = struct{}{}
		if !pluginname.ValidPaper(input.GetPluginName()) {
			return localjob.Job{}, fmt.Errorf("adapt Paper job: dependencies[%d].plugin_name is missing or invalid", index)
		}
		pluginNameKey := strings.ToLower(input.GetPluginName())
		if _, exists := seenPluginNames[pluginNameKey]; exists {
			return localjob.Job{}, fmt.Errorf("adapt Paper job: dependency plugin name %q is duplicated", input.GetPluginName())
		}
		seenPluginNames[pluginNameKey] = struct{}{}
		configured, exists := configuredDependencies[input.GetDependencyId()]
		if !exists {
			return localjob.Job{}, fmt.Errorf("adapt Paper job: dependency %q is absent from normalized configuration", input.GetDependencyId())
		}
		reference, digest, err := downloadReference(fmt.Sprintf("dependencies[%d].object", index), input.GetObject(), limits.maximumArtifactBytes)
		if err != nil {
			return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
		}
		expected, exists := dependencyHashes[input.GetDependencyId()]
		if !exists {
			return localjob.Job{}, fmt.Errorf("adapt Paper job: hashes.dependencies is missing %q", input.GetDependencyId())
		}
		if expected.filename != reference.Filename || expected.digest != digest {
			return localjob.Job{}, fmt.Errorf("adapt Paper job: hashes.dependencies entry for %q does not match its download", input.GetDependencyId())
		}
		dependencies = append(dependencies, dependencyReference{ID: input.GetDependencyId(), Plugin: input.GetPluginName(), Artifact: reference})
		if configured.Required {
			requiredDependencies = append(requiredDependencies, input.GetPluginName())
		}
	}
	if len(dependencyHashes) != len(dependencies) {
		return localjob.Job{}, errors.New("adapt Paper job: hashes.dependencies does not match the dependency downloads")
	}
	for id, dependency := range configuredDependencies {
		if dependency.Required {
			if _, exists := seenDependencies[id]; !exists {
				return localjob.Job{}, fmt.Errorf("adapt Paper job: required dependency %q has no download", id)
			}
		}
	}

	configuration := configuration{
		ArtifactKind:  ArtifactKindMinecraftPlugin,
		EnvironmentID: p.catalog.EnvironmentID,
		Target:        target,
		Dependencies:  dependencies,
		TestPlan: testPlan{
			TargetPlugin:              specification.GetTargetPluginName(),
			RequiredDependencies:      requiredDependencies,
			StabilizationMilliseconds: normalized.Tests.Startup.StabilizationSeconds * 1_000,
			Console:                   console,
		},
		MemoryBytes:  memoryBytes,
		CPUMillis:    int64(policy.GetResources().GetCpuMillis()),
		PIDs:         int64(policy.GetResources().GetProcessCount()),
		DiskBytes:    diskBytes,
		MaxLineBytes: defaultMaximumLineBytes,
	}
	encodedPlan, err := json.Marshal(configuration.TestPlan)
	if err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: encode test plan: %w", err)
	}
	if len(encodedPlan) > maximumProbePlanBytes {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: materialized test plan exceeds %d bytes", maximumProbePlanBytes)
	}
	if _, err := resolveConfiguration(configuration, p.catalog, p.inputPolicy, limits); err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}
	environment, err := json.Marshal(configuration)
	if err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: encode environment: %w", err)
	}
	if len(environment) > maximumNormalizedConfigurationBytes {
		return localjob.Job{}, errors.New("adapt Paper job: materialized environment exceeds 1048576 bytes")
	}

	job := localjob.Job{
		SchemaVersion:                       localjob.SchemaVersion,
		ID:                                  specification.GetLease().GetJobId(),
		Provider:                            ProviderName,
		TimeoutMilliseconds:                 executionTimeout.Milliseconds(),
		PreparationTimeoutMilliseconds:      preparationTimeout.Milliseconds(),
		GracefulShutdownTimeoutMilliseconds: gracefulShutdownTimeout.Milliseconds(),
		MaxOutputBytes:                      normalized.Resources.LogBytes,
		Environment:                         environment,
	}
	if err := job.Validate(); err != nil {
		return localjob.Job{}, fmt.Errorf("adapt Paper job: %w", err)
	}
	return job, nil
}

func (p *Provider) validateRemoteEnvironment(environment *runnerv1.ResolvedEnvironment) error {
	if environment == nil {
		return errors.New("environment is required")
	}
	if environment.GetProvider() != runnerv1.ServerProvider_SERVER_PROVIDER_PAPER {
		return errors.New("environment.provider must be Paper")
	}
	if environment.GetGameVersion() != p.catalog.Paper.GameVersion || environment.GetServerBuild() != p.catalog.Paper.Build {
		return errors.New("environment does not match the pinned Paper game version and build")
	}
	if environment.GetJavaDistribution() != p.catalog.Java.Distribution || environment.GetJavaVersion() != p.catalog.Java.Version {
		return errors.New("environment does not match the pinned Java distribution and version")
	}
	if environment.GetOperatingSystem() != runnerv1.OperatingSystem_OPERATING_SYSTEM_LINUX || environment.GetArchitecture() != runnerv1.Architecture_ARCHITECTURE_AMD64 {
		return errors.New("environment must target Linux amd64")
	}
	return nil
}

func decodeNormalizedConfiguration(data []byte) (normalizedConfiguration, []consoleCommandTest, error) {
	if len(data) == 0 || len(data) > maximumNormalizedConfigurationBytes {
		return normalizedConfiguration{}, nil, errors.New("normalized_configuration_json must contain between 1 and 1048576 bytes")
	}
	if !utf8.Valid(data) {
		return normalizedConfiguration{}, nil, errors.New("normalized_configuration_json must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var configuration normalizedConfiguration
	if err := decoder.Decode(&configuration); err != nil {
		return normalizedConfiguration{}, nil, fmt.Errorf("decode normalized_configuration_json: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return normalizedConfiguration{}, nil, errors.New("normalized_configuration_json must contain one JSON value")
	}
	if configuration.APIVersion != "provenance.dev/v1" {
		return normalizedConfiguration{}, nil, errors.New("normalized_configuration_json apiVersion must be provenance.dev/v1")
	}
	if configuration.Project == nil || configuration.Project.Name == "" {
		return normalizedConfiguration{}, nil, errors.New("normalized_configuration_json project.name is required")
	}
	if configuration.Tests == nil || configuration.Tests.Startup == nil || len(configuration.Tests.Console) == 0 {
		return normalizedConfiguration{}, nil, errors.New("normalized_configuration_json tests.startup and tests.console are required")
	}
	if configuration.Tests.Startup.StabilizationSeconds < 1 || configuration.Tests.Startup.StabilizationSeconds > 60 {
		return normalizedConfiguration{}, nil, errors.New("normalized_configuration_json tests.startup.stabilizationSeconds must be between 1 and 60 for the Paper probe")
	}
	if configuration.Resources == nil || configuration.Resources.LogBytes <= 0 {
		return normalizedConfiguration{}, nil, errors.New("normalized_configuration_json resources.logBytes must be positive")
	}
	var console []consoleCommandTest
	if err := json.Unmarshal(configuration.Tests.Console, &console); err != nil || console == nil {
		return normalizedConfiguration{}, nil, errors.New("normalized_configuration_json tests.console must be an array")
	}
	if err := validateConsoleTests(console); err != nil {
		return normalizedConfiguration{}, nil, err
	}
	return configuration, console, nil
}

func validateConsoleTests(tests []consoleCommandTest) error {
	if len(tests) > 100 {
		return errors.New("normalized_configuration_json tests.console exceeds 100 commands")
	}
	seen := make(map[string]struct{}, len(tests))
	events := 0
	for index, test := range tests {
		path := fmt.Sprintf("normalized_configuration_json tests.console[%d]", index)
		if len(test.ID) > 63 || !consoleIdentifier.MatchString(test.ID) {
			return fmt.Errorf("%s.id is invalid", path)
		}
		if _, exists := seen[test.ID]; exists {
			return errors.New("normalized_configuration_json tests.console ids must be unique")
		}
		seen[test.ID] = struct{}{}
		if utf8.RuneCountInString(test.Command) < 1 || utf8.RuneCountInString(test.Command) > 500 || strings.ContainsAny(test.Command, "\r\n\x00") {
			return fmt.Errorf("%s.command is invalid", path)
		}
		if test.TimeoutSeconds < 1 || test.TimeoutSeconds > 86_400 {
			return fmt.Errorf("%s.timeoutSeconds must be between 1 and 86400", path)
		}
		if len(test.Assertions) < 1 || len(test.Assertions) > 20 {
			return fmt.Errorf("%s.assertions must contain between 1 and 20 entries", path)
		}
		for assertionIndex, assertion := range test.Assertions {
			assertionPath := fmt.Sprintf("%s.assertions[%d]", path, assertionIndex)
			if assertion.Stream != "stdout" && assertion.Stream != "stderr" && assertion.Stream != "combined" {
				return fmt.Errorf("%s.stream is unsupported", assertionPath)
			}
			if assertion.Operator != "" && assertion.Operator != "contains" && assertion.Operator != "regex" {
				return fmt.Errorf("%s.operator is unsupported", assertionPath)
			}
			if utf8.RuneCountInString(assertion.Pattern) < 1 || utf8.RuneCountInString(assertion.Pattern) > 1_000 {
				return fmt.Errorf("%s.pattern is invalid", assertionPath)
			}
			if assertion.Match != "present" && assertion.Match != "absent" {
				return fmt.Errorf("%s.match is unsupported", assertionPath)
			}
			if assertion.MinimumOccurrences != nil {
				if *assertion.MinimumOccurrences < 1 || *assertion.MinimumOccurrences > 10_000 || assertion.Match == "absent" {
					return fmt.Errorf("%s.minimumOccurrences is invalid", assertionPath)
				}
			}
		}
		events += 6 + len(test.Assertions)
		if events > 512 {
			return errors.New("normalized_configuration_json tests.console exceeds the 512-event evidence budget")
		}
	}
	return nil
}

func remoteTimeout(field string, duration *durationpb.Duration) (time.Duration, error) {
	if duration == nil {
		return 0, fmt.Errorf("%s is required", field)
	}
	if err := duration.CheckValid(); err != nil {
		return 0, fmt.Errorf("%s is invalid", field)
	}
	value := duration.AsDuration()
	if value <= 0 || value > localjob.MaximumTimeout || value%time.Millisecond != 0 {
		return 0, fmt.Errorf("%s must be a whole number of milliseconds between 1 and %d", field, localjob.MaximumTimeout.Milliseconds())
	}
	return value, nil
}

func boundedInt64(name string, value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("%s exceeds the supported integer boundary", name)
	}
	return int64(value), nil
}

func downloadReference(name string, object *runnerv1.ObjectDownload, maximumBytes int64) (artifactReference, string, error) {
	if object == nil {
		return artifactReference{}, "", fmt.Errorf("%s is required", name)
	}
	if object.GetSizeBytes() <= 0 {
		return artifactReference{}, "", fmt.Errorf("%s.size_bytes must be positive", name)
	}
	if object.GetSizeBytes() > maximumBytes {
		return artifactReference{}, "", fmt.Errorf("%s.size_bytes exceeds the configured %d-byte artifact quota", name, maximumBytes)
	}
	digest, err := sha256Digest(name+".digest", object.GetDigest())
	if err != nil {
		return artifactReference{}, "", err
	}
	return artifactReference{URI: object.GetUri(), SHA256: digest, Filename: object.GetFilename(), SizeBytes: object.GetSizeBytes()}, digest, nil
}

func validateConfigurationDigest(hashes *runnerv1.JobHashes, data []byte) error {
	if hashes == nil {
		return errors.New("hashes is required")
	}
	expected, err := sha256Digest("hashes.configuration", hashes.GetConfiguration())
	if err != nil {
		return err
	}
	actual := sha256.Sum256(data)
	if expected != hex.EncodeToString(actual[:]) {
		return errors.New("hashes.configuration does not match normalized_configuration_json")
	}
	return nil
}

func requireMatchingDigest(name string, expected *runnerv1.Digest, actual string) error {
	value, err := sha256Digest(name, expected)
	if err != nil {
		return err
	}
	if value != actual {
		return fmt.Errorf("%s does not match its download", name)
	}
	return nil
}

func sha256Digest(name string, digest *runnerv1.Digest) (string, error) {
	if digest == nil || digest.GetAlgorithm() != runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 || len(digest.GetValue()) != sha256.Size {
		return "", fmt.Errorf("%s must be a 32-byte SHA-256 digest", name)
	}
	return hex.EncodeToString(digest.GetValue()), nil
}

type dependencyHash struct {
	filename string
	digest   string
}

func remoteDependencyHashes(hashes *runnerv1.JobHashes) (map[string]dependencyHash, error) {
	if hashes == nil {
		return nil, errors.New("hashes is required")
	}
	result := make(map[string]dependencyHash, len(hashes.GetDependencies()))
	for index, dependency := range hashes.GetDependencies() {
		if dependency == nil || dependency.GetDependencyId() == "" || dependency.GetFilename() == "" {
			return nil, fmt.Errorf("hashes.dependencies[%d] is incomplete", index)
		}
		if _, exists := result[dependency.GetDependencyId()]; exists {
			return nil, fmt.Errorf("hashes.dependencies contains duplicate %q", dependency.GetDependencyId())
		}
		digest, err := sha256Digest(fmt.Sprintf("hashes.dependencies[%d].digest", index), dependency.GetDigest())
		if err != nil {
			return nil, err
		}
		result[dependency.GetDependencyId()] = dependencyHash{filename: dependency.GetFilename(), digest: digest}
	}
	return result, nil
}
