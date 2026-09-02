package paper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/workspace"
)

const (
	ProviderName                   = "paper"
	ArtifactKindMinecraftPlugin    = "minecraft-plugin"
	minimumMemoryBytes             = int64(512 << 20)
	maximumDependencies            = 128
	defaultMaximumArtifactBytes    = int64(512 << 20)
	defaultMaximumDependencyBytes  = int64(1 << 30)
	defaultMaximumPreparationBytes = int64(2 << 30)
	probeEventKind                 = "paper_probe_event"
	workspaceSeedFailureExitCode   = 125
)

var safePluginName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_. -]{0,63}$`)

type Config struct {
	ArtifactCache           *artifact.Cache
	PaperCache              *artifact.Cache
	JavaCache               *artifact.Cache
	ProbeCache              *artifact.Cache
	RuntimeCache            *artifact.Cache
	Workspaces              *workspace.Manager
	Sandbox                 execution.IsolatedWorkloadProvider
	Catalog                 Catalog
	HTTPClient              *http.Client
	ArtifactHosts           []string
	MaximumArtifactBytes    int64
	MaximumDependencyBytes  int64
	MaximumPreparationBytes int64
	AllowHostileFixtures    bool
	inputPolicy             sourcePolicy
	pinPolicy               sourcePolicy
	sourceResolver          addressResolver
	sourceDialer            contextDialer
}

type Provider struct {
	config         Config
	catalog        resolvedCatalog
	inputPolicy    sourcePolicy
	pinPolicy      sourcePolicy
	sourceResolver addressResolver
	sourceDialer   contextDialer
}

var _ execution.EnvironmentProvider = (*Provider)(nil)

type resolvedCatalog struct {
	Catalog
	paperDigest   artifact.Digest
	javaDigest    artifact.Digest
	probeDigest   artifact.Digest
	runtimeDigest artifact.Digest
}

func New(config Config) (*Provider, error) {
	if config.ArtifactCache == nil || config.PaperCache == nil || config.JavaCache == nil || config.ProbeCache == nil || config.RuntimeCache == nil {
		return nil, errors.New("create Paper provider: artifact, Paper, Java, probe, and prepared runtime caches are required")
	}
	if config.Workspaces == nil {
		return nil, errors.New("create Paper provider: workspace manager is required")
	}
	if config.Sandbox == nil {
		return nil, errors.New("create Paper provider: isolated workload provider is required")
	}
	if config.MaximumArtifactBytes == 0 {
		config.MaximumArtifactBytes = defaultMaximumArtifactBytes
	}
	if config.MaximumDependencyBytes == 0 {
		config.MaximumDependencyBytes = defaultMaximumDependencyBytes
	}
	if config.MaximumPreparationBytes == 0 {
		config.MaximumPreparationBytes = defaultMaximumPreparationBytes
	}
	if config.MaximumArtifactBytes < 1 || config.MaximumDependencyBytes < 1 || config.MaximumPreparationBytes < 1 {
		return nil, errors.New("create Paper provider: preparation limits must be positive")
	}
	if config.MaximumPreparationBytes > 64<<30 || config.MaximumArtifactBytes > config.MaximumPreparationBytes || config.MaximumDependencyBytes > config.MaximumPreparationBytes {
		return nil, errors.New("create Paper provider: preparation limits exceed the supported aggregate boundary")
	}
	if config.Catalog.EnvironmentID == "" {
		config.Catalog = AlphaCatalog()
	}
	resolved, err := validateCatalog(config.Catalog)
	if err != nil {
		return nil, fmt.Errorf("create Paper provider: %w", err)
	}
	for _, pin := range []ArtifactPin{resolved.Paper.Artifact, resolved.Java.Artifact, resolved.Probe, resolved.PreparedRuntime.Artifact} {
		if pin.SizeBytes > config.MaximumArtifactBytes {
			return nil, fmt.Errorf("create Paper provider: pinned artifact %q exceeds the per-artifact limit", pin.Filename)
		}
	}
	inputPolicy := config.inputPolicy
	if inputPolicy == nil {
		inputPolicy, err = newHTTPSAllowlist(config.ArtifactHosts)
		if err != nil {
			return nil, fmt.Errorf("create Paper provider: artifact source policy: %w", err)
		}
	}
	pinPolicy := config.pinPolicy
	if pinPolicy == nil {
		pinPolicy, err = newPinnedSourcePolicy(config.Catalog)
		if err != nil {
			return nil, fmt.Errorf("create Paper provider: pinned source policy: %w", err)
		}
	}
	return &Provider{config: config, catalog: resolved, inputPolicy: inputPolicy, pinPolicy: pinPolicy, sourceResolver: config.sourceResolver, sourceDialer: config.sourceDialer}, nil
}

func (*Provider) Name() string {
	return ProviderName
}

type artifactReference struct {
	URI       string `json:"uri"`
	SHA256    string `json:"sha256"`
	Filename  string `json:"filename"`
	SizeBytes int64  `json:"sizeBytes"`
}

type dependencyReference struct {
	ID       string            `json:"id"`
	Plugin   string            `json:"plugin"`
	Artifact artifactReference `json:"artifact"`
}

type testPlan struct {
	TargetPlugin              string               `json:"targetPlugin"`
	RequiredDependencies      []string             `json:"requiredDependencies,omitempty"`
	StabilizationMilliseconds int64                `json:"stabilizationMilliseconds,omitempty"`
	Console                   []consoleCommandTest `json:"console,omitempty"`
}

type consoleCommandTest struct {
	ID             string             `json:"id"`
	Command        string             `json:"command"`
	TimeoutSeconds int64              `json:"timeoutSeconds"`
	Assertions     []commandAssertion `json:"assertions"`
}

type commandAssertion struct {
	Stream             string `json:"stream"`
	Operator           string `json:"operator,omitempty"`
	Pattern            string `json:"pattern"`
	Match              string `json:"match"`
	MinimumOccurrences *int64 `json:"minimumOccurrences,omitempty"`
}

type configuration struct {
	ArtifactKind  string                `json:"artifactKind"`
	EnvironmentID string                `json:"environmentId"`
	Target        artifactReference     `json:"target"`
	Dependencies  []dependencyReference `json:"dependencies,omitempty"`
	TestPlan      testPlan              `json:"testPlan"`
	MemoryBytes   int64                 `json:"memoryBytes"`
	CPUMillis     int64                 `json:"cpuMillis"`
	PIDs          int64                 `json:"pids"`
	DiskBytes     int64                 `json:"diskBytes"`
	MaxLineBytes  int64                 `json:"maxLineBytes,omitempty"`
	RedactSecrets []string              `json:"redactSecrets,omitempty"`
}

type resolvedReference struct {
	artifactReference
	digest artifact.Digest
}

type resolvedDependency struct {
	ID       string
	Plugin   string
	Artifact resolvedReference
}

type resolvedConfiguration struct {
	configuration
	target       resolvedReference
	dependencies []resolvedDependency
}

func (p *Provider) Resolve(ctx context.Context, request execution.Request) (execution.Environment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Environment))
	decoder.DisallowUnknownFields()
	var config configuration
	if err := decoder.Decode(&config); err != nil {
		return nil, invalidEnvironment(fmt.Errorf("decode Paper environment: %w", err))
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, invalidEnvironment(errors.New("multiple environment JSON values are not allowed"))
		}
		return nil, invalidEnvironment(fmt.Errorf("decode trailing environment data: %w", err))
	}
	resolved, err := resolveConfiguration(config, p.catalog, p.inputPolicy, preparationLimits{
		maximumArtifactBytes:    p.config.MaximumArtifactBytes,
		maximumDependencyBytes:  p.config.MaximumDependencyBytes,
		maximumPreparationBytes: p.config.MaximumPreparationBytes,
	})
	if err != nil {
		return nil, invalidEnvironment(err)
	}
	return &environment{provider: p, request: request, config: resolved}, nil
}

func invalidEnvironment(err error) error {
	return execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_paper_environment", err)
}

type preparationLimits struct {
	maximumArtifactBytes    int64
	maximumDependencyBytes  int64
	maximumPreparationBytes int64
}

func resolveConfiguration(config configuration, catalog resolvedCatalog, policy sourcePolicy, limits preparationLimits) (resolvedConfiguration, error) {
	if config.ArtifactKind != ArtifactKindMinecraftPlugin {
		return resolvedConfiguration{}, fmt.Errorf("artifactKind must be %q", ArtifactKindMinecraftPlugin)
	}
	if config.EnvironmentID != catalog.EnvironmentID {
		return resolvedConfiguration{}, fmt.Errorf("environmentId must be the pinned catalog entry %q", catalog.EnvironmentID)
	}
	if !safePluginName.MatchString(config.TestPlan.TargetPlugin) {
		return resolvedConfiguration{}, errors.New("testPlan.targetPlugin is invalid")
	}
	if config.TestPlan.StabilizationMilliseconds < 0 || config.TestPlan.StabilizationMilliseconds > 60_000 {
		return resolvedConfiguration{}, errors.New("testPlan.stabilizationMilliseconds must be between 0 and 60000")
	}
	if len(config.Dependencies) > maximumDependencies {
		return resolvedConfiguration{}, fmt.Errorf("dependencies must contain at most %d entries", maximumDependencies)
	}
	if config.MemoryBytes < minimumMemoryBytes || config.MemoryBytes > 64<<30 {
		return resolvedConfiguration{}, errors.New("memoryBytes must be between 536870912 and 68719476736")
	}
	if config.CPUMillis < 10 || config.CPUMillis > 64_000 {
		return resolvedConfiguration{}, errors.New("cpuMillis must be between 10 and 64000")
	}
	if config.PIDs < 1 || config.PIDs > 4_096 {
		return resolvedConfiguration{}, errors.New("pids must be between 1 and 4096")
	}
	if config.DiskBytes < 1<<20 || config.DiskBytes > 64<<30 {
		return resolvedConfiguration{}, errors.New("diskBytes must be between 1048576 and 68719476736")
	}
	target, err := resolveReference("target", config.Target, policy, limits.maximumArtifactBytes)
	if err != nil {
		return resolvedConfiguration{}, err
	}
	seenIDs := make(map[string]struct{}, len(config.Dependencies))
	seenPlugins := map[string]struct{}{strings.ToLower(config.TestPlan.TargetPlugin): {}}
	dependencies := make([]resolvedDependency, 0, len(config.Dependencies))
	var dependencyBytes int64
	for index, dependency := range config.Dependencies {
		if dependency.ID == "" || len(dependency.ID) > 128 || strings.ContainsAny(dependency.ID, "\\/\x00") {
			return resolvedConfiguration{}, fmt.Errorf("dependencies[%d].id is invalid", index)
		}
		if _, exists := seenIDs[dependency.ID]; exists {
			return resolvedConfiguration{}, fmt.Errorf("dependencies[%d].id is duplicated", index)
		}
		seenIDs[dependency.ID] = struct{}{}
		if !safePluginName.MatchString(dependency.Plugin) {
			return resolvedConfiguration{}, fmt.Errorf("dependencies[%d].plugin is invalid", index)
		}
		pluginKey := strings.ToLower(dependency.Plugin)
		if _, exists := seenPlugins[pluginKey]; exists {
			return resolvedConfiguration{}, fmt.Errorf("dependencies[%d].plugin is duplicated", index)
		}
		seenPlugins[pluginKey] = struct{}{}
		resolved, err := resolveReference(fmt.Sprintf("dependencies[%d].artifact", index), dependency.Artifact, policy, limits.maximumArtifactBytes)
		if err != nil {
			return resolvedConfiguration{}, err
		}
		if resolved.SizeBytes > limits.maximumDependencyBytes-dependencyBytes {
			return resolvedConfiguration{}, fmt.Errorf("dependency artifacts exceed the aggregate %d-byte limit", limits.maximumDependencyBytes)
		}
		dependencyBytes += resolved.SizeBytes
		dependencies = append(dependencies, resolvedDependency{ID: dependency.ID, Plugin: dependency.Plugin, Artifact: resolved})
	}
	for _, required := range config.TestPlan.RequiredDependencies {
		if _, exists := seenPlugins[strings.ToLower(required)]; !exists || !safePluginName.MatchString(required) {
			return resolvedConfiguration{}, fmt.Errorf("required dependency %q is not a configured dependency plugin", required)
		}
	}
	resolved := resolvedConfiguration{configuration: config, target: target, dependencies: dependencies}
	if err := validatePreparationBudget(resolved, catalog, dependencyBytes, limits); err != nil {
		return resolvedConfiguration{}, err
	}
	return resolved, nil
}

func resolveReference(name string, reference artifactReference, policy sourcePolicy, maximumBytes int64) (resolvedReference, error) {
	parsed, err := url.ParseRequestURI(reference.URI)
	if err != nil {
		return resolvedReference{}, fmt.Errorf("%s.uri: invalid URL", name)
	}
	if err := policy.ValidateInitial(parsed); err != nil {
		return resolvedReference{}, fmt.Errorf("%s.uri: %w", name, err)
	}
	if reference.Filename == "" || filepath.Base(reference.Filename) != reference.Filename || !strings.HasSuffix(strings.ToLower(reference.Filename), ".jar") {
		return resolvedReference{}, fmt.Errorf("%s.filename must be a plain JAR filename", name)
	}
	if reference.SizeBytes <= 0 || reference.SizeBytes > maximumBytes {
		return resolvedReference{}, fmt.Errorf("%s.sizeBytes must be between 1 and %d", name, maximumBytes)
	}
	digest, err := artifact.ParseSHA256(reference.SHA256)
	if err != nil {
		return resolvedReference{}, fmt.Errorf("%s.sha256: %w", name, err)
	}
	return resolvedReference{artifactReference: reference, digest: digest}, nil
}

func validatePreparationBudget(config resolvedConfiguration, catalog resolvedCatalog, dependencyBytes int64, limits preparationLimits) error {
	artifacts := []int64{
		catalog.Paper.Artifact.SizeBytes,
		catalog.Java.Artifact.SizeBytes,
		catalog.Probe.SizeBytes,
		catalog.PreparedRuntime.Artifact.SizeBytes,
		config.target.SizeBytes,
		dependencyBytes,
	}
	var downloads int64
	for _, size := range artifacts {
		if size == 0 {
			continue
		}
		if size < 0 || size > limits.maximumPreparationBytes-downloads {
			return fmt.Errorf("declared downloads exceed the aggregate %d-byte preparation limit", limits.maximumPreparationBytes)
		}
		downloads += size
	}
	workspaceSeed := catalog.PreparedRuntime.MaximumExpandedBytes + catalog.Paper.Artifact.SizeBytes + catalog.Probe.SizeBytes + config.target.SizeBytes + dependencyBytes + 64<<10
	if workspaceSeed < 0 || workspaceSeed > (config.DiskBytes+1)/2 {
		return errors.New("diskBytes is too small for the declared prepared server and plugin artifacts")
	}
	hostBytes := downloads + catalog.Java.MaximumExpandedBytes + workspaceSeed
	if hostBytes < downloads || hostBytes > limits.maximumPreparationBytes {
		return fmt.Errorf("cache and workspace preparation exceed the aggregate %d-byte limit", limits.maximumPreparationBytes)
	}
	return nil
}

type environment struct {
	provider *Provider
	request  execution.Request
	config   resolvedConfiguration
}

func (e *environment) Identity() string {
	return fmt.Sprintf("paper/%s/build-%d/paper-sha256:%s/%s/%s/java-sha256:%s/probe/%s/source-commit:%s/probe-sha256:%s/runtime-sha256:%s/delegate:%s", e.provider.catalog.Paper.GameVersion, e.provider.catalog.Paper.Build, e.provider.catalog.paperDigest, e.provider.catalog.Java.Distribution, e.provider.catalog.Java.Version, e.provider.catalog.javaDigest, e.provider.catalog.ProbeVersion, e.provider.catalog.ProbeSourceCommit, e.provider.catalog.probeDigest, e.provider.catalog.runtimeDigest, e.provider.config.Sandbox.Identity())
}

func (e *environment) ResourceClass() execution.ResourceClass {
	return execution.ResourceClass{
		CPUMillis:                      e.config.CPUMillis,
		MemoryBytes:                    e.config.MemoryBytes,
		ProcessCount:                   e.config.PIDs,
		DiskBytes:                      e.config.DiskBytes,
		Network:                        "none",
		MaximumConnections:             0,
		MaximumBandwidthBytesPerSecond: 0,
	}
}

type acquiredArtifacts struct {
	paper           *artifact.Entry
	java            *artifact.Entry
	probe           *artifact.Entry
	preparedRuntime *artifact.Entry
	target          *artifact.Entry
	dependencies    []*artifact.Entry
}

func (e *environment) Prepare(ctx context.Context) (execution.PreparedEnvironment, error) {
	acquired, err := e.acquire(ctx)
	if err != nil {
		return nil, err
	}
	jobWorkspace, err := e.provider.config.Workspaces.Create(ctx, e.request.JobID)
	if err != nil {
		return nil, fmt.Errorf("create Paper workspace: %w", err)
	}
	prepared := &preparedEnvironment{workspace: jobWorkspace, plan: e.config.TestPlan}
	workload, err := e.materialize(ctx, jobWorkspace, acquired)
	if err != nil {
		return prepared, err
	}
	sandboxEnvironment, err := e.provider.config.Sandbox.ResolveWorkload(ctx, e.request, workload)
	if err != nil {
		return prepared, fmt.Errorf("resolve Paper sandbox: %w", err)
	}
	if sandboxEnvironment == nil {
		return prepared, errors.New("resolve Paper sandbox: provider returned nil environment")
	}
	delegate, prepareErr := sandboxEnvironment.Prepare(ctx)
	prepared.delegate = delegate
	if prepareErr != nil {
		return prepared, fmt.Errorf("prepare Paper sandbox: %w", prepareErr)
	}
	if delegate == nil {
		return prepared, errors.New("prepare Paper sandbox: provider returned nil prepared environment")
	}
	return prepared, nil
}

func (e *environment) acquire(ctx context.Context) (acquiredArtifacts, error) {
	paperEntry, err := e.acquirePin(ctx, e.provider.config.PaperCache, e.provider.catalog.Paper.Artifact, e.provider.catalog.paperDigest)
	if err != nil {
		return acquiredArtifacts{}, fmt.Errorf("acquire Paper server: %w", err)
	}
	javaEntry, err := e.acquirePin(ctx, e.provider.config.JavaCache, e.provider.catalog.Java.Artifact, e.provider.catalog.javaDigest)
	if err != nil {
		return acquiredArtifacts{}, fmt.Errorf("acquire Java runtime: %w", err)
	}
	probeEntry, err := e.acquirePin(ctx, e.provider.config.ProbeCache, e.provider.catalog.Probe, e.provider.catalog.probeDigest)
	if err != nil {
		return acquiredArtifacts{}, fmt.Errorf("acquire trusted Paper probe: %w", err)
	}
	runtimeEntry, err := e.acquirePin(ctx, e.provider.config.RuntimeCache, e.provider.catalog.PreparedRuntime.Artifact, e.provider.catalog.runtimeDigest)
	if err != nil {
		return acquiredArtifacts{}, fmt.Errorf("acquire prepared Paper runtime: %w", err)
	}
	target, err := e.acquireReference(ctx, e.config.target)
	if err != nil {
		return acquiredArtifacts{}, fmt.Errorf("acquire target plugin: %w", err)
	}
	dependencies := make([]*artifact.Entry, 0, len(e.config.dependencies))
	for _, dependency := range e.config.dependencies {
		entry, err := e.acquireReference(ctx, dependency.Artifact)
		if err != nil {
			return acquiredArtifacts{}, fmt.Errorf("acquire dependency %q: %w", dependency.ID, err)
		}
		dependencies = append(dependencies, entry)
	}
	return acquiredArtifacts{paper: paperEntry, java: javaEntry, probe: probeEntry, preparedRuntime: runtimeEntry, target: target, dependencies: dependencies}, nil
}

func (e *environment) acquirePin(ctx context.Context, cache *artifact.Cache, pin ArtifactPin, digest artifact.Digest) (*artifact.Entry, error) {
	source, err := e.provider.source(pin.URI, pin.SizeBytes, e.provider.pinPolicy)
	if err != nil {
		return nil, err
	}
	entry, err := cache.AcquireExact(ctx, digest, pin.SizeBytes, source)
	if err != nil {
		return nil, err
	}
	if entry.Size() != pin.SizeBytes {
		return nil, fmt.Errorf("artifact size is %d bytes, want declared %d", entry.Size(), pin.SizeBytes)
	}
	return entry, nil
}

func (e *environment) acquireReference(ctx context.Context, reference resolvedReference) (*artifact.Entry, error) {
	source, err := e.provider.source(reference.URI, reference.SizeBytes, e.provider.inputPolicy)
	if err != nil {
		return nil, err
	}
	entry, err := e.provider.config.ArtifactCache.AcquireExact(ctx, reference.digest, reference.SizeBytes, source)
	if err != nil {
		return nil, err
	}
	if entry.Size() != reference.SizeBytes {
		return nil, fmt.Errorf("artifact size is %d bytes, want declared %d", entry.Size(), reference.SizeBytes)
	}
	return entry, nil
}

func (p *Provider) source(uri string, sizeBytes int64, policy sourcePolicy) (artifact.Source, error) {
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, errors.New("invalid artifact URL")
	}
	if err := policy.ValidateInitial(parsed); err != nil {
		return nil, err
	}
	client, err := clientWithSourcePolicy(p.config.HTTPClient, policy, p.sourceResolver, p.sourceDialer)
	if err != nil {
		return nil, err
	}
	return artifact.HTTPSource{URL: parsed.String(), UserAgent: DownloadUserAgent, Client: client, ExpectedBytes: sizeBytes}, nil
}

func (e *environment) materialize(ctx context.Context, jobWorkspace *workspace.Workspace, acquired acquiredArtifacts) (execution.IsolatedWorkload, error) {
	javaRoot, err := jobWorkspace.ExtractTarGzipBounded(ctx, "runtime", acquired.java, e.provider.catalog.Java.MaximumExpandedBytes)
	if err != nil {
		return execution.IsolatedWorkload{}, fmt.Errorf("extract Java runtime: %w", err)
	}
	javaHome := filepath.Join(javaRoot, filepath.FromSlash(e.provider.catalog.Java.ArchiveRoot))
	javaExecutable := filepath.Join(javaHome, "bin", "java")
	info, err := os.Stat(javaExecutable)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return execution.IsolatedWorkload{}, errors.New("extracted Java runtime does not contain an executable bin/java")
	}
	if _, err := jobWorkspace.ExtractTarGzipBounded(ctx, "server", acquired.preparedRuntime, e.provider.catalog.PreparedRuntime.MaximumExpandedBytes); err != nil {
		return execution.IsolatedWorkload{}, fmt.Errorf("extract prepared Paper runtime: %w", err)
	}
	if _, err := jobWorkspace.Materialize(ctx, "server/paper.jar", acquired.paper); err != nil {
		return execution.IsolatedWorkload{}, err
	}
	if _, err := jobWorkspace.Materialize(ctx, "server/plugins/target.jar", acquired.target); err != nil {
		return execution.IsolatedWorkload{}, err
	}
	if _, err := jobWorkspace.Materialize(ctx, "server/plugins/provenance-probe.jar", acquired.probe); err != nil {
		return execution.IsolatedWorkload{}, err
	}
	for index, entry := range acquired.dependencies {
		_, err := jobWorkspace.Materialize(ctx, fmt.Sprintf("server/plugins/dependency-%03d.jar", index), entry)
		if err != nil {
			return execution.IsolatedWorkload{}, err
		}
	}
	if _, err := jobWorkspace.WriteFile(ctx, "server/eula.txt", []byte("eula=true\n"), 0o400); err != nil {
		return execution.IsolatedWorkload{}, err
	}
	if _, err := jobWorkspace.WriteFile(ctx, "server/server.properties", []byte(minimalServerProperties), 0o400); err != nil {
		return execution.IsolatedWorkload{}, err
	}
	planJSON, err := json.MarshalIndent(e.config.TestPlan, "", "  ")
	if err != nil {
		return execution.IsolatedWorkload{}, fmt.Errorf("encode Paper test plan: %w", err)
	}
	planJSON = append(planJSON, '\n')
	if _, err := jobWorkspace.WriteFile(ctx, "server/provenance-test-plan.json", planJSON, 0o400); err != nil {
		return execution.IsolatedWorkload{}, err
	}
	if err := jobWorkspace.MakeSandboxReadable(ctx); err != nil {
		return execution.IsolatedWorkload{}, fmt.Errorf("publish Paper workspace to sandbox: %w", err)
	}
	required := append([]string(nil), e.config.TestPlan.RequiredDependencies...)
	sort.Strings(required)
	maximumHeapMiB := e.config.MemoryBytes * 3 / 4 / (1 << 20)
	javaArguments := []string{
		"-Xms256M",
		"-Xmx" + strconv.FormatInt(maximumHeapMiB, 10) + "M",
		"-Dhttp.agent=" + DownloadUserAgent,
		"-Dprovenance.probe.target=" + e.config.TestPlan.TargetPlugin,
		"-Dprovenance.probe.requiredDependencies=" + strings.Join(required, ","),
		"-Dprovenance.probe.events=/workspace/provenance-probe-events.ndjson",
		"-Dprovenance.probe.testPlan=/workspace/provenance-test-plan.json",
		"-Dprovenance.probe.stabilizationMillis=" + strconv.FormatInt(e.config.TestPlan.StabilizationMilliseconds, 10),
		"-Dprovenance.probe.requestShutdown=true",
	}
	if e.provider.config.AllowHostileFixtures {
		javaArguments = append(javaArguments, "-Dprovenance.fixture.hostile.enabled=true")
	}
	javaArguments = append(javaArguments, "-jar", "/workspace/paper.jar", "--nogui")
	arguments := []string{
		"-cu",
		`cp -R /inputs/server/. /workspace/ || exit 125; chmod -R u+rwX /workspace || exit 125; "$@"; status=$?; if [ "$status" -eq 125 ]; then exit 126; fi; exit "$status"`,
		"provenance-paper",
		"/runtime/bin/java",
	}
	arguments = append(arguments, javaArguments...)
	return execution.IsolatedWorkload{
		Command:        "/bin/sh",
		Arguments:      arguments,
		Environment:    map[string]string{"JAVA_HOME": "/runtime"},
		InputsPath:     jobWorkspace.Root(),
		ReadOnlyMounts: []execution.ReadOnlyMount{{Source: javaHome, Destination: "/runtime", Executable: true}},
		Network:        "none",
		MemoryBytes:    e.config.MemoryBytes,
		CPUMillis:      e.config.CPUMillis,
		PIDs:           e.config.PIDs,
		DiskBytes:      e.config.DiskBytes,
		MaxLineBytes:   e.config.MaxLineBytes,
		RedactSecrets:  append([]string(nil), e.config.RedactSecrets...),
		StructuredEventFile: &execution.StructuredEventFile{
			Destination:  "/workspace/provenance-probe-events.ndjson",
			Kind:         probeEventKind,
			MaximumBytes: 4 << 20,
		},
	}, nil
}

const minimalServerProperties = `allow-flight=false
enable-command-block=false
enable-jmx-monitoring=false
enable-query=false
enable-rcon=false
enforce-secure-profile=false
generate-structures=false
level-name=world
max-players=1
motd=Provenance ephemeral test
online-mode=false
server-ip=127.0.0.1
server-port=0
spawn-animals=false
spawn-monsters=false
spawn-npcs=false
view-distance=2
`

type preparedEnvironment struct {
	mu                sync.Mutex
	workspace         *workspace.Workspace
	delegate          execution.PreparedEnvironment
	cleaned           bool
	workspaceSeedFail bool
	plan              testPlan
}

func (p *preparedEnvironment) AttachObserver(observer execution.ExecutionObserver) {
	if delegate, ok := p.delegate.(execution.ObserverAttacher); ok {
		delegate.AttachObserver(observer)
	}
}

func (p *preparedEnvironment) Execute(ctx context.Context) (execution.ExecutionOutcome, error) {
	if p.delegate == nil {
		return execution.ExecutionOutcome{}, errors.New("execute Paper environment: sandbox was not prepared")
	}
	outcome, err := p.delegate.Execute(ctx)
	if outcome.ExitCode != nil && *outcome.ExitCode == workspaceSeedFailureExitCode {
		p.mu.Lock()
		p.workspaceSeedFail = true
		p.mu.Unlock()
		outcome.Failure = execution.NewFailure(execution.ClassificationInfrastructureFailure, "paper_workspace_seed_failed", "sandbox could not seed its writable Paper workspace")
		return outcome, nil
	}
	return outcome, err
}

func (p *preparedEnvironment) Collect(ctx context.Context) (execution.CollectedOutput, error) {
	if p.delegate == nil {
		return execution.CollectedOutput{}, nil
	}
	output, err := p.delegate.Collect(ctx)
	if err != nil {
		return output, err
	}
	p.mu.Lock()
	workspaceSeedFail := p.workspaceSeedFail
	p.mu.Unlock()
	if workspaceSeedFail {
		return output, nil
	}
	events, lifecycleErr := validateProbeLifecycle(output, p.plan)
	output.StructuredEvents = events
	output.EvidenceUsage.StructuredEventCount = int64(len(events))
	output.EvidenceUsage.StructuredEventBytes = 0
	for _, event := range events {
		output.EvidenceUsage.StructuredEventBytes += int64(len(event.Payload))
	}
	if lifecycleErr != nil {
		code := "paper_lifecycle_failed"
		var classified *probeLifecycleFailure
		if errors.As(lifecycleErr, &classified) {
			code = classified.code
		}
		return output, execution.NewClassifiedError(execution.ClassificationWorkloadFailure, code, lifecycleErr)
	}
	return output, nil
}

func (p *preparedEnvironment) Cleanup(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cleaned {
		return nil
	}
	var cleanupErrors []error
	if p.delegate != nil {
		cleanupErrors = append(cleanupErrors, p.delegate.Cleanup(ctx))
	}
	cleanupErrors = append(cleanupErrors, p.workspace.Cleanup(ctx))
	err := errors.Join(cleanupErrors...)
	if err == nil {
		p.cleaned = true
	}
	return err
}

func validateCatalog(catalog Catalog) (resolvedCatalog, error) {
	if catalog.EnvironmentID == "" || catalog.Paper.GameVersion == "" || catalog.Paper.Build == 0 {
		return resolvedCatalog{}, errors.New("catalog Paper identity is incomplete")
	}
	if catalog.Java.Distribution == "" || catalog.Java.Version == "" || catalog.Java.OS != "linux" || catalog.Java.Architecture != "amd64" || catalog.Java.ArchiveRoot == "" {
		return resolvedCatalog{}, errors.New("catalog Java identity must be a Linux amd64 runtime with an archive root")
	}
	if catalog.ProbeVersion == "" || catalog.ProbeSourceCommit == "" {
		return resolvedCatalog{}, errors.New("catalog probe version and source commit are required")
	}
	if strings.ContainsAny(catalog.Java.ArchiveRoot, "\\/") || catalog.Java.ArchiveRoot == "." || catalog.Java.ArchiveRoot == ".." {
		return resolvedCatalog{}, errors.New("catalog Java archive root is invalid")
	}
	if err := validatePin("Paper", catalog.Paper.Artifact); err != nil {
		return resolvedCatalog{}, err
	}
	if err := validatePin("Java", catalog.Java.Artifact); err != nil {
		return resolvedCatalog{}, err
	}
	if err := validatePin("probe", catalog.Probe); err != nil {
		return resolvedCatalog{}, err
	}
	if err := validatePin("prepared runtime", catalog.PreparedRuntime.Artifact); err != nil {
		return resolvedCatalog{}, err
	}
	if catalog.Java.MaximumExpandedBytes <= 0 || catalog.Java.MaximumExpandedBytes > 1<<30 || catalog.PreparedRuntime.MaximumExpandedBytes <= 0 || catalog.PreparedRuntime.MaximumExpandedBytes > 1<<30 {
		return resolvedCatalog{}, errors.New("catalog archive expanded-byte limits must be between 1 and 1073741824")
	}
	paperDigest, err := artifact.ParseSHA256(catalog.Paper.Artifact.SHA256)
	if err != nil {
		return resolvedCatalog{}, fmt.Errorf("catalog Paper SHA-256: %w", err)
	}
	javaDigest, err := artifact.ParseSHA256(catalog.Java.Artifact.SHA256)
	if err != nil {
		return resolvedCatalog{}, fmt.Errorf("catalog Java SHA-256: %w", err)
	}
	probeDigest, err := artifact.ParseSHA256(catalog.Probe.SHA256)
	if err != nil {
		return resolvedCatalog{}, fmt.Errorf("catalog probe SHA-256: %w", err)
	}
	runtimeDigest, err := artifact.ParseSHA256(catalog.PreparedRuntime.Artifact.SHA256)
	if err != nil {
		return resolvedCatalog{}, fmt.Errorf("catalog prepared runtime SHA-256: %w", err)
	}
	return resolvedCatalog{Catalog: catalog, paperDigest: paperDigest, javaDigest: javaDigest, probeDigest: probeDigest, runtimeDigest: runtimeDigest}, nil
}

func validatePin(name string, pin ArtifactPin) error {
	parsed, err := url.ParseRequestURI(pin.URI)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("catalog %s URI must be an HTTPS URL without credentials or a fragment", name)
	}
	if pin.Filename == "" || filepath.Base(pin.Filename) != pin.Filename {
		return fmt.Errorf("catalog %s filename is invalid", name)
	}
	if pin.SizeBytes <= 0 {
		return fmt.Errorf("catalog %s size must be positive", name)
	}
	return nil
}
