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
	ProviderName                = "paper"
	ArtifactKindMinecraftPlugin = "minecraft-plugin"
	minimumMemoryBytes          = int64(512 << 20)
	maximumDependencies         = 128
)

var safePluginName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_. -]{0,63}$`)

type Config struct {
	ArtifactCache   *artifact.Cache
	PaperCache      *artifact.Cache
	JavaCache       *artifact.Cache
	Workspaces      *workspace.Manager
	Sandbox         execution.IsolatedWorkloadProvider
	RuntimePreparer RuntimePreparer
	Catalog         Catalog
	HTTPClient      *http.Client
	ArtifactHosts   []string
	inputPolicy     sourcePolicy
	pinPolicy       sourcePolicy
}

type Provider struct {
	config      Config
	catalog     resolvedCatalog
	inputPolicy sourcePolicy
	pinPolicy   sourcePolicy
}

var _ execution.EnvironmentProvider = (*Provider)(nil)

type resolvedCatalog struct {
	Catalog
	paperDigest artifact.Digest
	javaDigest  artifact.Digest
}

func New(config Config) (*Provider, error) {
	if config.ArtifactCache == nil || config.PaperCache == nil || config.JavaCache == nil {
		return nil, errors.New("create Paper provider: artifact, Paper, and Java caches are required")
	}
	if config.Workspaces == nil {
		return nil, errors.New("create Paper provider: workspace manager is required")
	}
	if config.Sandbox == nil {
		return nil, errors.New("create Paper provider: isolated workload provider is required")
	}
	if config.RuntimePreparer == nil {
		config.RuntimePreparer = commandRuntimePreparer{}
	}
	if config.Catalog.EnvironmentID == "" {
		config.Catalog = AlphaCatalog()
	}
	resolved, err := validateCatalog(config.Catalog)
	if err != nil {
		return nil, fmt.Errorf("create Paper provider: %w", err)
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
	return &Provider{config: config, catalog: resolved, inputPolicy: inputPolicy, pinPolicy: pinPolicy}, nil
}

func (*Provider) Name() string {
	return ProviderName
}

type artifactReference struct {
	URI      string `json:"uri"`
	SHA256   string `json:"sha256"`
	Filename string `json:"filename"`
}

type dependencyReference struct {
	ID       string            `json:"id"`
	Plugin   string            `json:"plugin"`
	Artifact artifactReference `json:"artifact"`
}

type testPlan struct {
	TargetPlugin              string   `json:"targetPlugin"`
	RequiredDependencies      []string `json:"requiredDependencies,omitempty"`
	StabilizationMilliseconds int64    `json:"stabilizationMilliseconds,omitempty"`
}

type configuration struct {
	ArtifactKind  string                `json:"artifactKind"`
	EnvironmentID string                `json:"environmentId"`
	Target        artifactReference     `json:"target"`
	Dependencies  []dependencyReference `json:"dependencies,omitempty"`
	Probe         artifactReference     `json:"probe"`
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
	probe        resolvedReference
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
	resolved, err := resolveConfiguration(config, p.catalog.EnvironmentID, p.inputPolicy)
	if err != nil {
		return nil, invalidEnvironment(err)
	}
	return &environment{provider: p, request: request, config: resolved}, nil
}

func invalidEnvironment(err error) error {
	return execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_paper_environment", err)
}

func resolveConfiguration(config configuration, environmentID string, policy sourcePolicy) (resolvedConfiguration, error) {
	if config.ArtifactKind != ArtifactKindMinecraftPlugin {
		return resolvedConfiguration{}, fmt.Errorf("artifactKind must be %q", ArtifactKindMinecraftPlugin)
	}
	if config.EnvironmentID != environmentID {
		return resolvedConfiguration{}, fmt.Errorf("environmentId must be the pinned catalog entry %q", environmentID)
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
	target, err := resolveReference("target", config.Target, policy)
	if err != nil {
		return resolvedConfiguration{}, err
	}
	probe, err := resolveReference("probe", config.Probe, policy)
	if err != nil {
		return resolvedConfiguration{}, err
	}
	seenIDs := make(map[string]struct{}, len(config.Dependencies))
	seenPlugins := map[string]struct{}{strings.ToLower(config.TestPlan.TargetPlugin): {}}
	dependencies := make([]resolvedDependency, 0, len(config.Dependencies))
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
		resolved, err := resolveReference(fmt.Sprintf("dependencies[%d].artifact", index), dependency.Artifact, policy)
		if err != nil {
			return resolvedConfiguration{}, err
		}
		dependencies = append(dependencies, resolvedDependency{ID: dependency.ID, Plugin: dependency.Plugin, Artifact: resolved})
	}
	for _, required := range config.TestPlan.RequiredDependencies {
		if _, exists := seenPlugins[strings.ToLower(required)]; !exists || !safePluginName.MatchString(required) {
			return resolvedConfiguration{}, fmt.Errorf("required dependency %q is not a configured dependency plugin", required)
		}
	}
	return resolvedConfiguration{configuration: config, target: target, probe: probe, dependencies: dependencies}, nil
}

func resolveReference(name string, reference artifactReference, policy sourcePolicy) (resolvedReference, error) {
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
	digest, err := artifact.ParseSHA256(reference.SHA256)
	if err != nil {
		return resolvedReference{}, fmt.Errorf("%s.sha256: %w", name, err)
	}
	return resolvedReference{artifactReference: reference, digest: digest}, nil
}

type environment struct {
	provider *Provider
	request  execution.Request
	config   resolvedConfiguration
}

func (e *environment) Identity() string {
	return fmt.Sprintf("paper/%s/build-%d/%s/%s/%s", e.provider.catalog.Paper.GameVersion, e.provider.catalog.Paper.Build, e.provider.catalog.Java.Distribution, e.provider.catalog.Java.Version, e.provider.catalog.EnvironmentID)
}

type acquiredArtifacts struct {
	paper        *artifact.Entry
	java         *artifact.Entry
	target       *artifact.Entry
	probe        *artifact.Entry
	dependencies []*artifact.Entry
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
	prepared := &preparedEnvironment{workspace: jobWorkspace}
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
	target, err := e.acquireReference(ctx, e.config.target)
	if err != nil {
		return acquiredArtifacts{}, fmt.Errorf("acquire target plugin: %w", err)
	}
	probe, err := e.acquireReference(ctx, e.config.probe)
	if err != nil {
		return acquiredArtifacts{}, fmt.Errorf("acquire Paper probe: %w", err)
	}
	dependencies := make([]*artifact.Entry, 0, len(e.config.dependencies))
	for _, dependency := range e.config.dependencies {
		entry, err := e.acquireReference(ctx, dependency.Artifact)
		if err != nil {
			return acquiredArtifacts{}, fmt.Errorf("acquire dependency %q: %w", dependency.ID, err)
		}
		dependencies = append(dependencies, entry)
	}
	return acquiredArtifacts{paper: paperEntry, java: javaEntry, target: target, probe: probe, dependencies: dependencies}, nil
}

func (e *environment) acquirePin(ctx context.Context, cache *artifact.Cache, pin ArtifactPin, digest artifact.Digest) (*artifact.Entry, error) {
	source, err := e.provider.source(pin.URI, e.provider.pinPolicy)
	if err != nil {
		return nil, err
	}
	return cache.Acquire(ctx, digest, source)
}

func (e *environment) acquireReference(ctx context.Context, reference resolvedReference) (*artifact.Entry, error) {
	source, err := e.provider.source(reference.URI, e.provider.inputPolicy)
	if err != nil {
		return nil, err
	}
	return e.provider.config.ArtifactCache.Acquire(ctx, reference.digest, source)
}

func (p *Provider) source(uri string, policy sourcePolicy) (artifact.Source, error) {
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, errors.New("invalid artifact URL")
	}
	if err := policy.ValidateInitial(parsed); err != nil {
		return nil, err
	}
	return artifact.HTTPSource{URL: parsed.String(), UserAgent: DownloadUserAgent, Client: clientWithRedirectPolicy(p.config.HTTPClient, policy)}, nil
}

func (e *environment) materialize(ctx context.Context, jobWorkspace *workspace.Workspace, acquired acquiredArtifacts) (execution.IsolatedWorkload, error) {
	javaRoot, err := jobWorkspace.ExtractTarGzip(ctx, "runtime", acquired.java)
	if err != nil {
		return execution.IsolatedWorkload{}, fmt.Errorf("extract Java runtime: %w", err)
	}
	javaHome := filepath.Join(javaRoot, filepath.FromSlash(e.provider.catalog.Java.ArchiveRoot))
	javaExecutable := filepath.Join(javaHome, "bin", "java")
	info, err := os.Stat(javaExecutable)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return execution.IsolatedWorkload{}, errors.New("extracted Java runtime does not contain an executable bin/java")
	}
	if _, err := jobWorkspace.Materialize(ctx, "server/paper.jar", acquired.paper); err != nil {
		return execution.IsolatedWorkload{}, err
	}
	if err := e.provider.config.RuntimePreparer.Prepare(ctx, RuntimePreparation{
		JavaExecutable:  javaExecutable,
		ServerDirectory: filepath.Join(jobWorkspace.Root(), "server"),
	}); err != nil {
		return execution.IsolatedWorkload{}, fmt.Errorf("prepare pinned Paper runtime: %w", err)
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
		"-Dprovenance.probe.stabilizationMillis=" + strconv.FormatInt(e.config.TestPlan.StabilizationMilliseconds, 10),
		"-Dprovenance.probe.requestShutdown=true",
		"-jar", "/workspace/paper.jar", "--nogui",
	}
	arguments := []string{
		"-ceu",
		`cp -R /inputs/server/. /workspace/; chmod -R u+rwX /workspace; exec "$@"`,
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
	mu        sync.Mutex
	workspace *workspace.Workspace
	delegate  execution.PreparedEnvironment
	cleaned   bool
}

func (p *preparedEnvironment) Execute(ctx context.Context) (execution.ExecutionOutcome, error) {
	if p.delegate == nil {
		return execution.ExecutionOutcome{}, errors.New("execute Paper environment: sandbox was not prepared")
	}
	return p.delegate.Execute(ctx)
}

func (p *preparedEnvironment) Collect(ctx context.Context) (execution.CollectedOutput, error) {
	if p.delegate == nil {
		return execution.CollectedOutput{}, nil
	}
	return p.delegate.Collect(ctx)
}

func (p *preparedEnvironment) Cleanup(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cleaned {
		return nil
	}
	if p.delegate != nil {
		if err := p.delegate.Cleanup(ctx); err != nil {
			return err
		}
	}
	if err := p.workspace.Cleanup(ctx); err != nil {
		return err
	}
	p.cleaned = true
	return nil
}

func validateCatalog(catalog Catalog) (resolvedCatalog, error) {
	if catalog.EnvironmentID == "" || catalog.Paper.GameVersion == "" || catalog.Paper.Build == 0 {
		return resolvedCatalog{}, errors.New("catalog Paper identity is incomplete")
	}
	if catalog.Java.Distribution == "" || catalog.Java.Version == "" || catalog.Java.OS != "linux" || catalog.Java.Architecture != "amd64" || catalog.Java.ArchiveRoot == "" {
		return resolvedCatalog{}, errors.New("catalog Java identity must be a Linux amd64 runtime with an archive root")
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
	paperDigest, err := artifact.ParseSHA256(catalog.Paper.Artifact.SHA256)
	if err != nil {
		return resolvedCatalog{}, fmt.Errorf("catalog Paper SHA-256: %w", err)
	}
	javaDigest, err := artifact.ParseSHA256(catalog.Java.Artifact.SHA256)
	if err != nil {
		return resolvedCatalog{}, fmt.Errorf("catalog Java SHA-256: %w", err)
	}
	return resolvedCatalog{Catalog: catalog, paperDigest: paperDigest, javaDigest: javaDigest}, nil
}

func validatePin(name string, pin ArtifactPin) error {
	parsed, err := url.ParseRequestURI(pin.URI)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("catalog %s URI must be an HTTPS URL without credentials or a fragment", name)
	}
	if pin.Filename == "" || filepath.Base(pin.Filename) != pin.Filename {
		return fmt.Errorf("catalog %s filename is invalid", name)
	}
	return nil
}
