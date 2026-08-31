package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
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

type providerRegistry struct {
	*execution.Registry
	instanceLock *instancelock.Lock
}

func (r *providerRegistry) Close() error {
	if r == nil {
		return nil
	}
	return r.instanceLock.Close()
}

func registryForProvider(ctx context.Context, providerName string, lookup environmentLookup) (*providerRegistry, error) {
	providers := []execution.EnvironmentProvider{processprovider.New()}
	var instanceLock *instancelock.Lock
	if providerName == paper.ProviderName {
		provider, lock, err := paperProviderFromEnvironment(ctx, lookup)
		if err != nil {
			return nil, err
		}
		instanceLock = lock
		providers = append(providers, provider)
	}
	registry, err := execution.NewRegistry(providers...)
	if err != nil {
		return nil, errors.Join(err, instanceLock.Close())
	}
	return &providerRegistry{Registry: registry, instanceLock: instanceLock}, nil
}

func paperProviderFromEnvironment(ctx context.Context, lookup environmentLookup) (*paper.Provider, *instancelock.Lock, error) {
	catalog, err := operatorCatalog(lookup)
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
	instanceLock, err := instancelock.Acquire(filepath.Join(bundleRoot, ".provenance-runner.lock"))
	if err != nil {
		return nil, nil, fmt.Errorf("initialize Paper runner instance: %w", err)
	}
	fail := func(constructionErr error) (*paper.Provider, *instancelock.Lock, error) {
		return nil, nil, errors.Join(constructionErr, instanceLock.Close())
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
		Catalog:                 catalog,
		ArtifactHosts:           artifactHosts,
		MaximumArtifactBytes:    maximumArtifactBytes,
		MaximumDependencyBytes:  maximumDependencyBytes,
		MaximumPreparationBytes: maximumPreparationBytes,
	})
	if err != nil {
		return fail(err)
	}
	return provider, instanceLock, nil
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
