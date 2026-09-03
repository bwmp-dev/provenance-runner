package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/instancelock"
	"github.com/bwmp-dev/provenance-runner/internal/provider/gvisor"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	processprovider "github.com/bwmp-dev/provenance-runner/internal/provider/process"
	"github.com/bwmp-dev/provenance-runner/internal/workspace"
)

type environmentLookup func(string) string

const maximumConfiguredStorageBytes = int64(64 << 30)
const gvisorReconciliationTimeout = 15 * time.Second
const localHostileFixturesEnvironment = "PROVENANCE_LOCAL_EXECUTE_ALLOW_HOSTILE_FIXTURES"

type paperProviderOptions struct {
	allowHostileFixtures bool
}

type providerRegistry struct {
	*execution.Registry
	instanceLocks *instancelock.Set
}

func (r *providerRegistry) Close() error {
	if r == nil {
		return nil
	}
	return r.instanceLocks.Close()
}

func registryForProvider(ctx context.Context, providerName string, lookup environmentLookup) (*providerRegistry, error) {
	return registryForProviderWithOptions(ctx, providerName, lookup, paperProviderOptions{})
}

func registryForLocalExecution(ctx context.Context, providerName string, lookup environmentLookup) (*providerRegistry, error) {
	allowHostileFixtures, err := localHostileFixturesOptIn(lookup)
	if err != nil {
		return nil, err
	}
	return registryForProviderWithOptions(ctx, providerName, lookup, paperProviderOptions{allowHostileFixtures: allowHostileFixtures})
}

func registryForProviderWithOptions(ctx context.Context, providerName string, lookup environmentLookup, options paperProviderOptions) (*providerRegistry, error) {
	providers := []execution.EnvironmentProvider{processprovider.New()}
	var instanceLocks *instancelock.Set
	if providerName == paper.ProviderName {
		provider, locks, err := paperProviderFromEnvironment(ctx, lookup, options)
		if err != nil {
			return nil, err
		}
		instanceLocks = locks
		providers = append(providers, provider)
	}
	registry, err := execution.NewRegistry(providers...)
	if err != nil {
		return nil, errors.Join(err, instanceLocks.Close())
	}
	return &providerRegistry{Registry: registry, instanceLocks: instanceLocks}, nil
}

func paperProviderFromEnvironment(ctx context.Context, lookup environmentLookup, options paperProviderOptions) (*paper.Provider, *instancelock.Set, error) {
	if err := validatePaperPlatform(runtime.GOOS, runtime.GOARCH); err != nil {
		return nil, nil, err
	}
	catalogs, err := operatorCatalogs(lookup)
	if err != nil {
		return nil, nil, err
	}
	workspaceRoot, err := requiredEnvironment(lookup, "PROVENANCE_WORKSPACE_ROOT")
	if err != nil {
		return nil, nil, err
	}
	cacheRoot, err := requiredEnvironment(lookup, "PROVENANCE_CACHE_ROOT")
	if err != nil {
		return nil, nil, err
	}
	artifactHosts, err := commaSeparatedEnvironment(lookup, "PROVENANCE_ARTIFACT_HOSTS")
	if err != nil {
		return nil, nil, err
	}
	maximumArtifactBytes, err := optionalPositiveInt64(lookup, "PROVENANCE_MAX_ARTIFACT_BYTES")
	if err != nil {
		return nil, nil, err
	}
	maximumDependencyBytes, err := optionalPositiveInt64(lookup, "PROVENANCE_MAX_DEPENDENCY_BYTES")
	if err != nil {
		return nil, nil, err
	}
	maximumPreparationBytes, err := optionalPositiveInt64(lookup, "PROVENANCE_MAX_PREPARATION_BYTES")
	if err != nil {
		return nil, nil, err
	}
	maximumCacheBytes, err := optionalPositiveInt64(lookup, "PROVENANCE_MAX_CACHE_BYTES")
	if err != nil {
		return nil, nil, err
	}
	if maximumCacheBytes == 0 {
		maximumCacheBytes = 8 << 30
	}
	if maximumCacheBytes > maximumConfiguredStorageBytes {
		return nil, nil, fmt.Errorf("PROVENANCE_MAX_CACHE_BYTES cannot exceed %d", maximumConfiguredStorageBytes)
	}
	cacheEntryLimit := maximumArtifactBytes
	if cacheEntryLimit == 0 {
		cacheEntryLimit = 512 << 20
	}
	if cacheEntryLimit > maximumCacheBytes {
		return nil, nil, errors.New("PROVENANCE_MAX_ARTIFACT_BYTES cannot exceed PROVENANCE_MAX_CACHE_BYTES")
	}
	runscPath, err := requiredEnvironment(lookup, "PROVENANCE_RUNSC_PATH")
	if err != nil {
		return nil, nil, err
	}
	rootFS, err := requiredEnvironment(lookup, "PROVENANCE_ROOTFS")
	if err != nil {
		return nil, nil, err
	}
	rootFSIdentity, err := requiredEnvironment(lookup, "PROVENANCE_ROOTFS_IDENTITY")
	if err != nil {
		return nil, nil, err
	}
	stateRoot, err := requiredEnvironment(lookup, "PROVENANCE_GVISOR_STATE_ROOT")
	if err != nil {
		return nil, nil, err
	}
	bundleRoot, err := requiredEnvironment(lookup, "PROVENANCE_GVISOR_BUNDLE_ROOT")
	if err != nil {
		return nil, nil, err
	}
	instanceLocks, err := instancelock.AcquireAll(
		filepath.Join(bundleRoot, ".provenance-runner.lock"),
		filepath.Join(workspaceRoot, ".provenance-runner.lock"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize Paper runner instance: %w", err)
	}
	fail := func(constructionErr error) (*paper.Provider, *instancelock.Set, error) {
		return nil, nil, errors.Join(constructionErr, instanceLocks.Close())
	}

	manager, err := workspace.NewManager(workspaceRoot)
	if err != nil {
		return fail(err)
	}
	sandbox, err := gvisor.New(gvisor.Config{
		RunscPath:      runscPath,
		RootFS:         rootFS,
		RootFSIdentity: rootFSIdentity,
		StateRoot:      stateRoot,
		BundleRoot:     bundleRoot,
		InputsRoot:     workspaceRoot,
		Platform:       lookup("PROVENANCE_GVISOR_PLATFORM"),
	})
	if err != nil {
		return fail(err)
	}
	reconcileContext, cancelReconcile := context.WithTimeout(ctx, gvisorReconciliationTimeout)
	defer cancelReconcile()
	if err := sandbox.Reconcile(reconcileContext); err != nil {
		return fail(fmt.Errorf("reconcile gVisor state: %w", err))
	}
	if err := manager.ReconcileOwnedAttempts(reconcileContext); err != nil {
		return fail(fmt.Errorf("reconcile owned attempt workspaces: %w", err))
	}

	sharedCache, err := artifact.NewCache(filepath.Join(cacheRoot, "content"), artifact.CacheOptions{
		MaximumEntryBytes: cacheEntryLimit,
		MaximumTotalBytes: maximumCacheBytes,
	})
	if err != nil {
		return fail(err)
	}
	provider, err := paper.New(paper.Config{
		ArtifactCache:           sharedCache,
		PaperCache:              sharedCache,
		JavaCache:               sharedCache,
		ProbeCache:              sharedCache,
		RuntimeCache:            sharedCache,
		Workspaces:              manager,
		Sandbox:                 sandbox,
		Catalogs:                catalogs,
		ArtifactHosts:           artifactHosts,
		MaximumArtifactBytes:    maximumArtifactBytes,
		MaximumDependencyBytes:  maximumDependencyBytes,
		MaximumPreparationBytes: maximumPreparationBytes,
		AllowHostileFixtures:    options.allowHostileFixtures,
	})
	if err != nil {
		return fail(err)
	}
	return provider, instanceLocks, nil
}

func validatePaperPlatform(goos, goarch string) error {
	if goos != "linux" || goarch != "amd64" {
		return fmt.Errorf("Paper provider requires linux/amd64, current platform is %s/%s", goos, goarch)
	}
	return nil
}

func localHostileFixturesOptIn(lookup environmentLookup) (bool, error) {
	switch lookup(localHostileFixturesEnvironment) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be exactly true or false when set", localHostileFixturesEnvironment)
	}
}

func operatorCatalog(lookup environmentLookup) (paper.Catalog, error) {
	catalog := paper.AlphaCatalog()
	probe, err := operatorArtifactPin(lookup, "PROVENANCE_PAPER_PROBE", "paper-probe.jar")
	if err != nil {
		return paper.Catalog{}, err
	}
	if probe.SHA256 != catalog.Probe.SHA256 || probe.SizeBytes != catalog.Probe.SizeBytes {
		return paper.Catalog{}, fmt.Errorf("PROVENANCE_PAPER_PROBE must be probe %s from %s with SHA-256 %s and size %d", catalog.ProbeVersion, catalog.ProbeSourceCommit, catalog.Probe.SHA256, catalog.Probe.SizeBytes)
	}
	runtimeArtifact, err := operatorArtifactPin(lookup, "PROVENANCE_PAPER_PREPARED_RUNTIME", "paper-prepared-runtime.tar.gz")
	if err != nil {
		return paper.Catalog{}, err
	}
	runtimeExpanded, err := requiredPositiveInt64(lookup, "PROVENANCE_PAPER_PREPARED_RUNTIME_MAX_EXPANDED_BYTES")
	if err != nil {
		return paper.Catalog{}, err
	}
	catalog.Probe = probe
	catalog.PreparedRuntime = paper.ArchivePin{Artifact: runtimeArtifact, MaximumExpandedBytes: runtimeExpanded}
	return catalog, nil
}

const preparedRuntimesEnvironment = "PROVENANCE_PAPER_PREPARED_RUNTIMES_JSON"

type preparedRuntimeConfiguration struct {
	EnvironmentID        string `json:"environmentId"`
	URI                  string `json:"uri"`
	SHA256               string `json:"sha256"`
	SizeBytes            int64  `json:"sizeBytes"`
	MaximumExpandedBytes int64  `json:"maximumExpandedBytes"`
}

func operatorCatalogs(lookup environmentLookup) ([]paper.Catalog, error) {
	raw := strings.TrimSpace(lookup(preparedRuntimesEnvironment))
	if raw == "" {
		catalog, err := operatorCatalog(lookup)
		if err != nil {
			return nil, err
		}
		return []paper.Catalog{catalog}, nil
	}
	for _, name := range []string{
		"PROVENANCE_PAPER_PREPARED_RUNTIME_URI",
		"PROVENANCE_PAPER_PREPARED_RUNTIME_SHA256",
		"PROVENANCE_PAPER_PREPARED_RUNTIME_SIZE_BYTES",
		"PROVENANCE_PAPER_PREPARED_RUNTIME_MAX_EXPANDED_BYTES",
	} {
		if strings.TrimSpace(lookup(name)) != "" {
			return nil, fmt.Errorf("%s cannot be combined with legacy PROVENANCE_PAPER_PREPARED_RUNTIME_* variables", preparedRuntimesEnvironment)
		}
	}
	if len(raw) > 64<<10 {
		return nil, fmt.Errorf("%s exceeds 65536 bytes", preparedRuntimesEnvironment)
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	var configured []preparedRuntimeConfiguration
	if err := decoder.Decode(&configured); err != nil {
		return nil, fmt.Errorf("%s must be a strict JSON array: %w", preparedRuntimesEnvironment, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s must contain exactly one JSON value", preparedRuntimesEnvironment)
	}
	baseCatalogs := paper.AlphaCatalogs()
	if len(configured) != len(baseCatalogs) {
		return nil, fmt.Errorf("%s must configure exactly %d alpha environments", preparedRuntimesEnvironment, len(baseCatalogs))
	}
	probe, err := operatorArtifactPin(lookup, "PROVENANCE_PAPER_PROBE", "paper-probe.jar")
	if err != nil {
		return nil, err
	}
	alpha := paper.AlphaCatalog()
	if probe.SHA256 != alpha.Probe.SHA256 || probe.SizeBytes != alpha.Probe.SizeBytes {
		return nil, fmt.Errorf("PROVENANCE_PAPER_PROBE must be probe %s from %s with SHA-256 %s and size %d", alpha.ProbeVersion, alpha.ProbeSourceCommit, alpha.Probe.SHA256, alpha.Probe.SizeBytes)
	}
	byID := make(map[string]preparedRuntimeConfiguration, len(configured))
	digests := make(map[string]string, len(configured))
	for _, runtime := range configured {
		if _, exists := byID[runtime.EnvironmentID]; exists {
			return nil, fmt.Errorf("%s contains duplicate environmentId %q", preparedRuntimesEnvironment, runtime.EnvironmentID)
		}
		if _, exists := paper.CatalogForEnvironmentID(runtime.EnvironmentID); !exists {
			return nil, fmt.Errorf("%s contains unrecognized environmentId %q", preparedRuntimesEnvironment, runtime.EnvironmentID)
		}
		pin, err := operatorArtifactPinValues(preparedRuntimesEnvironment, runtime.URI, runtime.SHA256, runtime.EnvironmentID+"-prepared-runtime.tar.gz", runtime.SizeBytes)
		if err != nil {
			return nil, err
		}
		if runtime.MaximumExpandedBytes <= 0 || runtime.MaximumExpandedBytes > 1<<30 {
			return nil, fmt.Errorf("%s maximumExpandedBytes must be between 1 and 1073741824", preparedRuntimesEnvironment)
		}
		if existing, exists := digests[pin.SHA256]; exists {
			return nil, fmt.Errorf("%s environments %q and %q cannot share a prepared-runtime digest", preparedRuntimesEnvironment, existing, runtime.EnvironmentID)
		}
		digests[pin.SHA256] = runtime.EnvironmentID
		byID[runtime.EnvironmentID] = runtime
	}
	result := make([]paper.Catalog, 0, len(baseCatalogs))
	for _, catalog := range baseCatalogs {
		runtime, exists := byID[catalog.EnvironmentID]
		if !exists {
			return nil, fmt.Errorf("%s is missing environmentId %q", preparedRuntimesEnvironment, catalog.EnvironmentID)
		}
		pin, err := operatorArtifactPinValues(preparedRuntimesEnvironment, runtime.URI, runtime.SHA256, catalog.EnvironmentID+"-prepared-runtime.tar.gz", runtime.SizeBytes)
		if err != nil {
			return nil, err
		}
		catalog.Probe = probe
		catalog.PreparedRuntime = paper.ArchivePin{Artifact: pin, MaximumExpandedBytes: runtime.MaximumExpandedBytes}
		result = append(result, catalog)
	}
	return result, nil
}

func operatorArtifactPin(lookup environmentLookup, prefix, filename string) (paper.ArtifactPin, error) {
	uri, err := requiredEnvironment(lookup, prefix+"_URI")
	if err != nil {
		return paper.ArtifactPin{}, err
	}
	digest, err := requiredEnvironment(lookup, prefix+"_SHA256")
	if err != nil {
		return paper.ArtifactPin{}, err
	}
	if _, err := artifact.ParseSHA256(digest); err != nil {
		return paper.ArtifactPin{}, fmt.Errorf("%s_SHA256: %w", prefix, err)
	}
	parsedURI, err := url.ParseRequestURI(uri)
	if err != nil || parsedURI.Scheme != "https" || parsedURI.Host == "" || parsedURI.User != nil || parsedURI.Fragment != "" {
		return paper.ArtifactPin{}, fmt.Errorf("%s_URI must be an HTTPS URL without credentials or a fragment", prefix)
	}
	size, err := requiredPositiveInt64(lookup, prefix+"_SIZE_BYTES")
	if err != nil {
		return paper.ArtifactPin{}, err
	}
	return paper.ArtifactPin{URI: uri, SHA256: digest, Filename: filename, SizeBytes: size}, nil
}

func operatorArtifactPinValues(name, uri, digest, filename string, size int64) (paper.ArtifactPin, error) {
	if _, err := artifact.ParseSHA256(digest); err != nil {
		return paper.ArtifactPin{}, fmt.Errorf("%s SHA-256 is invalid: %w", name, err)
	}
	parsedURI, err := url.ParseRequestURI(uri)
	if err != nil || parsedURI.Scheme != "https" || parsedURI.Host == "" || parsedURI.User != nil || parsedURI.Fragment != "" {
		return paper.ArtifactPin{}, fmt.Errorf("%s URI must be an HTTPS URL without credentials or a fragment", name)
	}
	if size <= 0 {
		return paper.ArtifactPin{}, fmt.Errorf("%s sizeBytes must be positive", name)
	}
	return paper.ArtifactPin{URI: uri, SHA256: digest, Filename: filename, SizeBytes: size}, nil
}

func requiredEnvironment(lookup environmentLookup, name string) (string, error) {
	value := strings.TrimSpace(lookup(name))
	if value == "" {
		return "", fmt.Errorf("%s is required for the Paper provider", name)
	}
	return value, nil
}

func commaSeparatedEnvironment(lookup environmentLookup, name string) ([]string, error) {
	value, err := requiredEnvironment(lookup, name)
	if err != nil {
		return nil, err
	}
	var values []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("%s contains an empty value", name)
		}
		values = append(values, item)
	}
	return values, nil
}

func requiredPositiveInt64(lookup environmentLookup, name string) (int64, error) {
	value, err := requiredEnvironment(lookup, name)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func optionalPositiveInt64(lookup environmentLookup, name string) (int64, error) {
	if strings.TrimSpace(lookup(name)) == "" {
		return 0, nil
	}
	return requiredPositiveInt64(lookup, name)
}
