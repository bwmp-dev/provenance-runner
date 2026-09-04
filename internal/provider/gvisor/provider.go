package gvisor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

const (
	ProviderName                       = "gvisor"
	CgroupDriverRunsc                  = "runsc"
	CgroupDriverSystemdUser            = "systemd-user"
	containerUID                uint32 = 65532
	containerGID                uint32 = 65532
	cleanupTimeout                     = 10 * time.Second
	metadataName                       = ".provenance-gvisor.json"
	attemptName                        = ".provenance-run-attempted"
	metadataVersion                    = 1
	metadataPhasePrepared              = "prepared"
	metadataPhaseAttempted             = "run_attempted"
	structuredEventFileName            = "structured-events.ndjson"
	maximumStructuredEventBytes        = int64(4 << 20)
)

// runsc reserves 128 for failures in the runtime command itself.
const runscFailureExitCode = 128

var safeJobID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Config struct {
	RunscPath         string
	CgroupDriver      string
	SystemdRunPath    string
	SystemdCgroupRoot string
	RootFS            string
	StateRoot         string
	BundleRoot        string
	InputsRoot        string
	Platform          string
	RootFSIdentity    string
	runtimeIdentity   string
	cgroupIdentity    string
}

type Provider struct {
	config Config
	runner commandRunner
}

var _ execution.EnvironmentProvider = (*Provider)(nil)
var _ execution.IsolatedWorkloadProvider = (*Provider)(nil)

func New(config Config) (*Provider, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("create gVisor provider: Linux is required, current OS is %s", runtime.GOOS)
	}
	runscPath := config.RunscPath
	if runscPath == "" {
		runscPath = "runsc"
	}
	resolvedRunsc, err := exec.LookPath(runscPath)
	if err != nil {
		return nil, fmt.Errorf("create gVisor provider: find runsc: %w", err)
	}
	config.RunscPath = resolvedRunsc
	runtimeIdentity, err := executableIdentity(resolvedRunsc)
	if err != nil {
		return nil, fmt.Errorf("create gVisor provider: identify runsc: %w", err)
	}
	config.runtimeIdentity = runtimeIdentity
	if config.CgroupDriver == "" {
		config.CgroupDriver = CgroupDriverRunsc
	}
	if config.CgroupDriver == CgroupDriverSystemdUser {
		systemdRunPath := config.SystemdRunPath
		if systemdRunPath == "" {
			systemdRunPath = "systemd-run"
		}
		resolvedSystemdRun, err := exec.LookPath(systemdRunPath)
		if err != nil {
			return nil, fmt.Errorf("create gVisor provider: find systemd-run: %w", err)
		}
		config.SystemdRunPath = resolvedSystemdRun
		config.cgroupIdentity, err = executableIdentity(resolvedSystemdRun)
		if err != nil {
			return nil, fmt.Errorf("create gVisor provider: identify systemd-run: %w", err)
		}
	}
	return newProvider(config, execCommandRunner{})
}

func newProvider(config Config, runner commandRunner) (*Provider, error) {
	if runner == nil {
		return nil, errors.New("create gVisor provider: command runner is nil")
	}
	if config.RunscPath == "" {
		return nil, errors.New("create gVisor provider: runsc path is empty")
	}
	if config.Platform == "" {
		config.Platform = "systrap"
	}
	if config.Platform != "systrap" && config.Platform != "kvm" {
		return nil, fmt.Errorf("create gVisor provider: unsupported platform %q", config.Platform)
	}
	if config.CgroupDriver == "" {
		config.CgroupDriver = CgroupDriverRunsc
	}
	switch config.CgroupDriver {
	case CgroupDriverRunsc:
		if config.SystemdRunPath != "" || config.SystemdCgroupRoot != "" || config.cgroupIdentity != "" {
			return nil, errors.New("create gVisor provider: systemd cgroup settings require the systemd-user driver")
		}
	case CgroupDriverSystemdUser:
		if config.SystemdRunPath == "" || config.cgroupIdentity == "" {
			return nil, errors.New("create gVisor provider: systemd-user driver requires an identified systemd-run executable")
		}
		var err error
		config.SystemdCgroupRoot, err = existingCgroupRoot(config.SystemdCgroupRoot)
		if err != nil {
			return nil, fmt.Errorf("create gVisor provider: %w", err)
		}
	default:
		return nil, fmt.Errorf("create gVisor provider: unsupported cgroup driver %q", config.CgroupDriver)
	}
	if config.RootFSIdentity == "" || len(config.RootFSIdentity) > 256 || strings.ContainsAny(config.RootFSIdentity, "\r\n") {
		return nil, errors.New("create gVisor provider: root filesystem identity is required")
	}
	if config.runtimeIdentity == "" {
		return nil, errors.New("create gVisor provider: runsc runtime identity is required")
	}

	var err error
	if config.RootFS, err = existingDirectory("root filesystem", config.RootFS); err != nil {
		return nil, fmt.Errorf("create gVisor provider: %w", err)
	}
	if config.InputsRoot, err = existingDirectory("inputs root", config.InputsRoot); err != nil {
		return nil, fmt.Errorf("create gVisor provider: %w", err)
	}
	if config.StateRoot, err = ownedDirectory("state root", config.StateRoot); err != nil {
		return nil, fmt.Errorf("create gVisor provider: %w", err)
	}
	if config.BundleRoot, err = ownedDirectory("bundle root", config.BundleRoot); err != nil {
		return nil, fmt.Errorf("create gVisor provider: %w", err)
	}
	paths := []struct {
		name string
		path string
	}{
		{name: "root filesystem", path: config.RootFS},
		{name: "inputs root", path: config.InputsRoot},
		{name: "state root", path: config.StateRoot},
		{name: "bundle root", path: config.BundleRoot},
	}
	for left := 0; left < len(paths); left++ {
		for right := left + 1; right < len(paths); right++ {
			if pathsOverlap(paths[left].path, paths[right].path) {
				return nil, fmt.Errorf("create gVisor provider: %s and %s must not overlap", paths[left].name, paths[right].name)
			}
		}
	}
	return &Provider{config: config, runner: runner}, nil
}

func (*Provider) Name() string {
	return ProviderName
}

func (p *Provider) Identity() string {
	identity := fmt.Sprintf("gvisor/%s/rootfs:%s/runsc:%s", p.config.Platform, p.config.RootFSIdentity, p.config.runtimeIdentity)
	if p.config.CgroupDriver == CgroupDriverSystemdUser {
		identity += "/cgroup:systemd-user/systemd-run:" + p.config.cgroupIdentity
	}
	return identity
}

func existingCgroupRoot(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("systemd cgroup root must be an absolute directory")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve systemd cgroup root: %w", err)
	}
	if resolved == "/sys/fs/cgroup" || !strings.HasPrefix(resolved, "/sys/fs/cgroup/") {
		return "", errors.New("systemd cgroup root must be a descendant of /sys/fs/cgroup")
	}
	if filepath.Base(resolved) != "app.slice" {
		return "", errors.New("systemd cgroup root must be the active user manager app.slice")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect systemd cgroup root: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("systemd cgroup root must be a directory")
	}
	relative, ok := currentUnifiedCgroup()
	if !ok {
		return "", errors.New("cannot identify the runner's unified cgroup")
	}
	current := filepath.Clean(filepath.Join("/sys/fs/cgroup", relative))
	if current != resolved && !strings.HasPrefix(current, resolved+string(filepath.Separator)) {
		return "", errors.New("runner process is outside the configured user manager app.slice")
	}
	return resolved, nil
}

func executableIdentity(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 512<<20 {
		return "", errors.New("runsc must be a bounded regular file")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

type configuration struct {
	Command       string            `json:"command"`
	Arguments     []string          `json:"arguments,omitempty"`
	Environment   map[string]string `json:"environment,omitempty"`
	Network       string            `json:"network,omitempty"`
	MemoryBytes   int64             `json:"memoryBytes"`
	CPUMillis     int64             `json:"cpuMillis"`
	PIDs          int64             `json:"pids"`
	DiskBytes     int64             `json:"diskBytes"`
	MaxLineBytes  int64             `json:"maxLineBytes,omitempty"`
	RedactSecrets []string          `json:"redactSecrets,omitempty"`
}

func (p *Provider) Resolve(ctx context.Context, request execution.Request) (execution.Environment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !safeJobID.MatchString(request.JobID) {
		return nil, invalidEnvironment(errors.New("job ID must contain only letters, numbers, dots, underscores, and hyphens and be at most 128 bytes"))
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Environment))
	decoder.DisallowUnknownFields()
	var config configuration
	if err := decoder.Decode(&config); err != nil {
		return nil, invalidEnvironment(fmt.Errorf("decode gVisor environment: %w", err))
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, invalidEnvironment(errors.New("multiple environment JSON values are not allowed"))
		}
		return nil, invalidEnvironment(fmt.Errorf("decode trailing environment data: %w", err))
	}
	inputs, err := p.jobInputs(request.JobID)
	if err != nil {
		return nil, execution.NewClassifiedError(execution.ClassificationInfrastructureFailure, "gvisor_inputs_unavailable", err)
	}
	return p.resolveWorkload(ctx, request, execution.IsolatedWorkload{
		Command:       config.Command,
		Arguments:     config.Arguments,
		Environment:   config.Environment,
		InputsPath:    inputs,
		Network:       config.Network,
		MemoryBytes:   config.MemoryBytes,
		CPUMillis:     config.CPUMillis,
		PIDs:          config.PIDs,
		DiskBytes:     config.DiskBytes,
		MaxLineBytes:  config.MaxLineBytes,
		RedactSecrets: config.RedactSecrets,
	})
}

func (p *Provider) ResolveWorkload(ctx context.Context, request execution.Request, workload execution.IsolatedWorkload) (execution.Environment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !safeJobID.MatchString(request.JobID) {
		return nil, invalidEnvironment(errors.New("job ID must contain only letters, numbers, dots, underscores, and hyphens and be at most 128 bytes"))
	}
	return p.resolveWorkload(ctx, request, workload)
}

func (p *Provider) resolveWorkload(ctx context.Context, request execution.Request, workload execution.IsolatedWorkload) (execution.Environment, error) {
	config := configuration{
		Command:       workload.Command,
		Arguments:     append([]string(nil), workload.Arguments...),
		Environment:   cloneMap(workload.Environment),
		Network:       workload.Network,
		MemoryBytes:   workload.MemoryBytes,
		CPUMillis:     workload.CPUMillis,
		PIDs:          workload.PIDs,
		DiskBytes:     workload.DiskBytes,
		MaxLineBytes:  workload.MaxLineBytes,
		RedactSecrets: append([]string(nil), workload.RedactSecrets...),
	}
	if err := validateConfiguration(config, request.Limits.MaxOutputBytes); err != nil {
		return nil, invalidEnvironment(err)
	}
	evidenceConfig := evidence.Config{
		MaxLineBytes:         config.MaxLineBytes,
		MaxTotalBytes:        request.Limits.MaxOutputBytes,
		Secrets:              append([]string(nil), config.RedactSecrets...),
		StructuredLinePrefix: workload.StructuredOutputPrefix,
		StructuredLineKind:   workload.StructuredOutputKind,
	}
	if err := evidence.ValidateConfig(evidenceConfig); err != nil {
		return nil, invalidEnvironment(err)
	}
	inputs, err := p.validateInputPath(workload.InputsPath)
	if err != nil {
		return nil, execution.NewClassifiedError(execution.ClassificationInfrastructureFailure, "gvisor_inputs_unavailable", err)
	}
	mounts, err := p.validateReadOnlyMounts(inputs, workload.ReadOnlyMounts)
	if err != nil {
		return nil, execution.NewClassifiedError(execution.ClassificationInfrastructureFailure, "gvisor_mounts_invalid", err)
	}
	structuredEventFile, err := validateStructuredEventFile(workload.StructuredEventFile)
	if err != nil {
		return nil, invalidEnvironment(err)
	}
	if structuredEventFile != nil && (workload.StructuredOutputPrefix != "" || workload.StructuredOutputKind != "") {
		return nil, invalidEnvironment(errors.New("structured event FIFO cannot be combined with the legacy stdout event channel"))
	}
	structuredEventPrefix := ""
	if structuredEventFile != nil {
		structuredEventPrefix, err = randomStructuredEventPrefix()
		if err != nil {
			return nil, execution.NewClassifiedError(execution.ClassificationInfrastructureFailure, "gvisor_event_channel_unavailable", err)
		}
		evidenceConfig.StructuredLinePrefix = structuredEventPrefix
		evidenceConfig.StructuredLineKind = structuredEventFile.Kind
		if err := evidence.ValidateConfig(evidenceConfig); err != nil {
			return nil, invalidEnvironment(err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &environment{
		provider:              p,
		config:                config,
		inputs:                inputs,
		mounts:                mounts,
		evidenceConfig:        evidenceConfig,
		structuredEventFile:   structuredEventFile,
		structuredEventPrefix: structuredEventPrefix,
	}, nil
}

func validateStructuredEventFile(requested *execution.StructuredEventFile) (*execution.StructuredEventFile, error) {
	if requested == nil {
		return nil, nil
	}
	if requested.Destination != "/tmp/provenance-probe-events.ndjson" {
		return nil, errors.New("structured event FIFO destination must be /tmp/provenance-probe-events.ndjson")
	}
	if requested.MaximumBytes < 1 || requested.MaximumBytes > maximumStructuredEventBytes {
		return nil, fmt.Errorf("structured event FIFO maximumBytes must be between 1 and %d", maximumStructuredEventBytes)
	}
	if err := evidence.ValidateConfig(evidence.Config{StructuredLinePrefix: "VALIDATE:", StructuredLineKind: requested.Kind}); err != nil {
		return nil, fmt.Errorf("structured event FIFO kind: %w", err)
	}
	validated := *requested
	return &validated, nil
}

func cloneMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func randomStructuredEventPrefix() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("create structured event channel identity: %w", err)
	}
	return "PROVENANCE_HOST_EVENT_" + hex.EncodeToString(value) + ":", nil
}

func invalidEnvironment(err error) error {
	return execution.NewClassifiedError(execution.ClassificationInvalidJob, "invalid_gvisor_environment", err)
}

func validateConfiguration(config configuration, maxOutputBytes int64) error {
	if strings.TrimSpace(config.Command) == "" || !strings.HasPrefix(config.Command, "/") || strings.ContainsRune(config.Command, '\x00') {
		return errors.New("command must be an absolute container path")
	}
	for _, argument := range config.Arguments {
		if strings.ContainsRune(argument, '\x00') {
			return errors.New("arguments cannot contain null bytes")
		}
	}
	for key, value := range config.Environment {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			return fmt.Errorf("environment variable name %q is invalid", key)
		}
		if strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("environment variable %q contains a null byte", key)
		}
	}
	if config.Network != "" && config.Network != "none" {
		return errors.New("only network=none is supported until policy-enforced egress is available")
	}
	if config.MemoryBytes < 16<<20 || config.MemoryBytes > 64<<30 {
		return errors.New("memoryBytes must be between 16777216 and 68719476736")
	}
	if config.CPUMillis < 10 || config.CPUMillis > 64_000 {
		return errors.New("cpuMillis must be between 10 and 64000")
	}
	if config.PIDs < 1 || config.PIDs > 4_096 {
		return errors.New("pids must be between 1 and 4096")
	}
	if config.DiskBytes < 1<<20 || config.DiskBytes > 64<<30 {
		return errors.New("diskBytes must be between 1048576 and 68719476736")
	}
	return evidence.ValidateConfig(evidence.Config{
		MaxLineBytes:  config.MaxLineBytes,
		MaxTotalBytes: maxOutputBytes,
		Secrets:       config.RedactSecrets,
	})
}

func (p *Provider) jobInputs(jobID string) (string, error) {
	return p.validateInputPath(filepath.Join(p.config.InputsRoot, jobID))
}

func (p *Provider) validateInputPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("job inputs path is empty")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect job inputs: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("job inputs must be a directory and cannot be a symbolic link")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve job inputs: %w", err)
	}
	if err := ensureDescendant(p.config.InputsRoot, resolved); err != nil {
		return "", fmt.Errorf("resolve job inputs: %w", err)
	}
	return resolved, nil
}

func (p *Provider) validateReadOnlyMounts(inputs string, requested []execution.ReadOnlyMount) ([]execution.ReadOnlyMount, error) {
	mounts := make([]execution.ReadOnlyMount, 0, len(requested))
	destinations := make(map[string]struct{}, len(requested))
	for _, mount := range requested {
		resolved, err := p.validateMountSource(inputs, mount.Source)
		if err != nil {
			return nil, fmt.Errorf("validate mount source: %w", err)
		}
		destination := filepath.ToSlash(filepath.Clean(mount.Destination))
		if !strings.HasPrefix(destination, "/") || destination == "/" || strings.ContainsRune(destination, '\x00') {
			return nil, fmt.Errorf("mount destination %q must be an absolute container path", mount.Destination)
		}
		if destination != "/runtime" && !strings.HasPrefix(destination, "/runtime/") && !strings.HasPrefix(destination, "/workspace/") {
			return nil, fmt.Errorf("mount destination %q is outside /runtime and /workspace", destination)
		}
		if _, exists := destinations[destination]; exists {
			return nil, fmt.Errorf("duplicate mount destination %q", destination)
		}
		destinations[destination] = struct{}{}
		mounts = append(mounts, execution.ReadOnlyMount{Source: resolved, Destination: destination, Executable: mount.Executable})
	}
	return mounts, nil
}

func (p *Provider) validateMountSource(inputs, path string) (string, error) {
	if path == "" {
		return "", errors.New("mount source is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err := ensureDescendant(inputs, absolute); err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return "", errors.New("mount source must be a regular file or directory and cannot be a symbolic link")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	if err := ensureDescendant(inputs, resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

type environment struct {
	provider              *Provider
	config                configuration
	inputs                string
	mounts                []execution.ReadOnlyMount
	evidenceConfig        evidence.Config
	structuredEventFile   *execution.StructuredEventFile
	structuredEventPrefix string
}

func (e *environment) Identity() string {
	return e.provider.Identity()
}

func (e *environment) ResourceClass() execution.ResourceClass {
	return execution.ResourceClass{
		CPUMillis:          e.config.CPUMillis,
		MemoryBytes:        e.config.MemoryBytes,
		ProcessCount:       e.config.PIDs,
		DiskBytes:          e.config.DiskBytes,
		Network:            "none",
		MaximumConnections: 0,
		// With no network stack, the effective bandwidth ceiling is zero.
		MaximumBandwidthBytesPerSecond: 0,
	}
}

func (e *environment) Prepare(ctx context.Context) (execution.PreparedEnvironment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	collector, err := evidence.NewCollector(e.evidenceConfig)
	if err != nil {
		return nil, fmt.Errorf("create gVisor evidence collector: %w", err)
	}
	containerID, err := randomContainerID()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create gVisor container ID: %w", err), collector.Close())
	}
	bundle, err := os.MkdirTemp(e.provider.config.BundleRoot, "provenance-bundle-")
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create gVisor bundle: %w", err), collector.Close())
	}
	prepared := &preparedEnvironment{
		provider:              e.provider,
		containerID:           containerID,
		bundle:                bundle,
		evidence:              collector,
		structuredEventFile:   e.structuredEventFile,
		structuredEventPrefix: e.structuredEventPrefix,
		cgroupLimits: cgroupLimits{
			memoryBytes: e.config.MemoryBytes,
			cpuMillis:   e.config.CPUMillis,
			pids:        e.config.PIDs,
		},
	}
	if err := prepared.writeMetadata(); err != nil {
		return nil, errors.Join(err, collector.Close(), os.RemoveAll(bundle))
	}
	var eventMount *structuredEventMount
	if e.structuredEventFile != nil {
		prepared.structuredEventPath = filepath.Join(bundle, structuredEventFileName)
		prepared.structuredEventChannel, err = createStructuredEventChannel(prepared.structuredEventPath, e.structuredEventFile.MaximumBytes)
		if err != nil {
			return nil, errors.Join(err, collector.Close(), os.RemoveAll(bundle))
		}
		eventMount = &structuredEventMount{source: prepared.structuredEventPath, destination: e.structuredEventFile.Destination}
	}
	spec, err := buildSpec(e.config, e.provider.config.RootFS, e.inputs, containerID, e.mounts, eventMount)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("build OCI config: %w", err), collector.Close(), os.RemoveAll(bundle))
	}
	if err := writeJSONFile(filepath.Join(bundle, "config.json"), spec); err != nil {
		return nil, errors.Join(fmt.Errorf("write OCI config: %w", err), collector.Close(), os.RemoveAll(bundle))
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, collector.Close(), os.RemoveAll(bundle))
	}
	return prepared, nil
}

type preparedEnvironment struct {
	mu                         sync.Mutex
	usageMu                    sync.Mutex
	provider                   *Provider
	containerID                string
	bundle                     string
	evidence                   *evidence.Collector
	cleaned                    bool
	observer                   execution.ExecutionObserver
	usage                      execution.ResourceUsage
	outerPIDDenials            uint64
	pidDenialEvidenceAvailable bool
	structuredEventPath        string
	structuredEventChannel     *structuredEventChannel
	structuredEventFile        *execution.StructuredEventFile
	structuredEventPrefix      string
	structuredEventErr         string
	cgroupLimits               cgroupLimits
	eventChannelMaximumBytes   int64
	eventChannelBufferedBytes  int64
	eventChannelResourceBytes  int64
	eventChannelOverflowed     bool
	eventChannelRemoved        bool
}

func (e *preparedEnvironment) AttachObserver(observer execution.ExecutionObserver) {
	e.usageMu.Lock()
	e.observer = observer
	e.usageMu.Unlock()
	e.evidence.SetLiveSink(func(entry evidence.LiveEntry) {
		observer.ObserveLog(execution.LiveLogEntry{Stream: string(entry.Stream), Data: entry.Data, Partial: entry.Partial, Redacted: entry.Redacted})
	})
}

func (e *preparedEnvironment) Execute(ctx context.Context) (execution.ExecutionOutcome, error) {
	if e.structuredEventChannel != nil {
		if err := e.structuredEventChannel.start(); err != nil {
			e.collectStructuredEvents()
			return execution.ExecutionOutcome{}, execution.NewClassifiedError(
				execution.ClassificationInfrastructureFailure,
				"gvisor_event_channel_unavailable",
				err,
			)
		}
		// The live host reader is finalized after every execution path, including
		// cancellation and non-zero sandbox teardown. Execution failures retain
		// precedence over any independently recorded channel failure.
		defer e.collectStructuredEvents()
	}
	stdout, err := e.evidence.RawWriter(evidence.StreamStdout)
	if err != nil {
		return execution.ExecutionOutcome{}, err
	}
	stderr, err := e.evidence.RawWriter(evidence.StreamStderr)
	if err != nil {
		return execution.ExecutionOutcome{}, err
	}
	if err := e.markRunAttempted(); err != nil {
		return execution.ExecutionOutcome{}, fmt.Errorf("mark gVisor run attempted: %w", err)
	}
	stopSampling := make(chan struct{})
	samplingDone := make(chan struct{})
	go e.sampleUsageUntil(stopSampling, samplingDone)
	runCommand, err := e.provider.wrapRunCommand(command{
		Path:   e.provider.config.RunscPath,
		Args:   e.provider.runArguments("run", "--bundle="+e.bundle, e.containerID),
		Stdout: stdout,
		Stderr: stderr,
	}, e.cgroupLimits, e.containerID)
	if err != nil {
		close(stopSampling)
		<-samplingDone
		return execution.ExecutionOutcome{}, fmt.Errorf("configure gVisor cgroup command: %w", err)
	}
	result := e.provider.runner.Run(ctx, runCommand)
	close(stopSampling)
	<-samplingDone
	e.sampleUsage()
	if ctx.Err() != nil {
		killContext, cancelKill := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancelKill()
		killResult := e.provider.runner.Run(killContext, command{
			Path: e.provider.config.RunscPath,
			Args: e.provider.runArguments("kill", "--all", e.containerID, "KILL"),
		})
		if killResult.Err != nil {
			return execution.ExecutionOutcome{ExitCode: result.ExitCode}, errors.Join(ctx.Err(), fmt.Errorf("kill cancelled gVisor container: %w", killResult.Err))
		}
		return execution.ExecutionOutcome{ExitCode: result.ExitCode}, ctx.Err()
	}
	e.usageMu.Lock()
	outerPIDDenials := e.outerPIDDenials
	denialEvidenceAvailable := e.pidDenialEvidenceAvailable
	e.usageMu.Unlock()
	return classifyRunResult(result, outerPIDDenials, denialEvidenceAvailable)
}

func classifyRunResult(result commandResult, outerPIDDenials uint64, denialEvidenceAvailable bool) (execution.ExecutionOutcome, error) {
	if denialEvidenceAvailable && outerPIDDenials > 0 {
		return execution.ExecutionOutcome{ExitCode: result.ExitCode}, execution.NewClassifiedError(
			execution.ClassificationInfrastructureFailure,
			"gvisor_runtime_pid_reserve_exhausted",
			fmt.Errorf("outer gVisor cgroup rejected %d process creations", outerPIDDenials),
		)
	}
	if result.Err == nil {
		return execution.ExecutionOutcome{ExitCode: result.ExitCode}, nil
	}
	if result.ExitCode != nil && *result.ExitCode != runscFailureExitCode {
		return execution.ExecutionOutcome{
			ExitCode: result.ExitCode,
			Failure:  execution.NewFailure(execution.ClassificationWorkloadFailure, "gvisor_process_exit_nonzero", fmt.Sprintf("sandboxed process exited with code %d", *result.ExitCode)),
		}, nil
	}
	return execution.ExecutionOutcome{ExitCode: result.ExitCode}, fmt.Errorf("run gVisor container: %w", result.Err)
}

func (e *preparedEnvironment) Collect(ctx context.Context) (execution.CollectedOutput, error) {
	if err := ctx.Err(); err != nil {
		return execution.CollectedOutput{}, err
	}
	bundle, err := e.evidence.Snapshot(ctx)
	if e.structuredEventErr != "" && bundle.StructuredEventError == "" {
		bundle.StructuredEventError = e.structuredEventErr
	}
	e.usageMu.Lock()
	usage := e.usage
	e.usageMu.Unlock()
	events := make([]execution.StructuredEvent, len(bundle.Events))
	for index, event := range bundle.Events {
		events[index] = execution.StructuredEvent{Sequence: event.Sequence, Kind: event.Kind, Payload: append([]byte(nil), event.Payload...)}
	}
	return execution.CollectedOutput{
		Stdout:           bundle.Stdout,
		Stderr:           bundle.Stderr,
		CapturedBytes:    bundle.Usage.CapturedBytes,
		ObservedBytes:    bundle.Usage.RawBytesObserved,
		OutputTruncated:  bundle.Usage.OutputTruncated,
		StructuredEvents: events,
		CompleteLog: &execution.CompleteLog{
			State:             bundle.CompleteLog.State,
			Truncated:         bundle.CompleteLog.Truncated,
			Error:             bundle.CompleteLog.Error,
			ContentType:       bundle.CompleteLog.ContentType,
			ContentEncoding:   bundle.CompleteLog.ContentEncoding,
			SHA256:            bundle.CompleteLog.SHA256,
			UncompressedBytes: bundle.CompleteLog.UncompressedBytes,
			CompressedBytes:   bundle.CompleteLog.CompressedBytes,
			Archive:           bundle.CompleteLog.Archive,
		},
		EvidenceUsage: execution.EvidenceUsage{
			RawBytesObserved:          bundle.Usage.RawBytesObserved,
			CapturedBytes:             bundle.Usage.CapturedBytes,
			StructuredEventCount:      bundle.Usage.StructuredEventCount,
			StructuredEventBytes:      bundle.Usage.StructuredEventBytes,
			CompleteLogBytes:          bundle.Usage.CompleteLogBytes,
			CompressedLogBytes:        bundle.Usage.CompressedLogBytes,
			TruncatedLineCount:        bundle.Usage.TruncatedLineCount,
			OutputTruncated:           bundle.Usage.OutputTruncated,
			CompleteLogState:          bundle.Usage.CompleteLogState,
			CompleteLogTruncated:      bundle.Usage.CompleteLogTruncated,
			EventsTruncated:           bundle.Usage.EventsTruncated,
			EventChannelMaximumBytes:  e.eventChannelMaximumBytes,
			EventChannelBufferedBytes: e.eventChannelBufferedBytes,
			EventChannelResourceBytes: e.eventChannelResourceBytes,
			EventChannelOverflowed:    e.eventChannelOverflowed,
			EventChannelRemoved:       e.eventChannelRemoved,
		},
		StructuredEventError: bundle.StructuredEventError,
		ResourceUsage:        &usage,
	}, err
}

func (e *preparedEnvironment) collectStructuredEvents() {
	if e.structuredEventChannel == nil {
		return
	}
	snapshot := e.structuredEventChannel.finish()
	defer clear(snapshot.content)
	e.eventChannelMaximumBytes = snapshot.maximum
	e.eventChannelBufferedBytes = snapshot.bufferedBytes
	e.eventChannelResourceBytes = snapshot.resourceBytes
	e.eventChannelOverflowed = snapshot.overflowed
	e.eventChannelRemoved = snapshot.removed
	if snapshot.readErr != nil {
		e.structuredEventErr = snapshot.readErr.Error()
		return
	}
	if snapshot.overflowed {
		e.structuredEventErr = fmt.Sprintf("structured event FIFO exceeds %d bytes", snapshot.maximum)
		return
	}
	content := snapshot.content
	if len(content) == 0 {
		return
	}
	if content[len(content)-1] != '\n' {
		e.structuredEventErr = "structured event FIFO has an unterminated final record"
		return
	}
	writer, err := e.evidence.RawWriter(evidence.StreamStdout)
	if err != nil {
		e.structuredEventErr = err.Error()
		return
	}
	for _, line := range bytes.Split(content[:len(content)-1], []byte{'\n'}) {
		if len(line) == 0 {
			e.structuredEventErr = "structured event FIFO contains an empty record"
			return
		}
		record := make([]byte, 0, len(e.structuredEventPrefix)+len(line)+1)
		record = append(record, e.structuredEventPrefix...)
		record = append(record, line...)
		record = append(record, '\n')
		if _, err := writer.Write(record); err != nil {
			e.structuredEventErr = err.Error()
			return
		}
	}
}

func (e *preparedEnvironment) Cleanup(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cleaned {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.structuredEventChannel != nil {
		e.structuredEventChannel.finish()
	}
	attempted, err := runWasAttempted(e.bundle)
	if err != nil {
		return fmt.Errorf("inspect gVisor run-attempt state: %w", err)
	}
	if attempted {
		result := e.provider.runner.Run(ctx, command{
			Path: e.provider.config.RunscPath,
			Args: e.provider.runArguments("delete", "--force", e.containerID),
		})
		if result.Err != nil {
			return fmt.Errorf("delete gVisor container: %w", result.Err)
		}
	}
	if err := e.evidence.Close(); err != nil {
		return fmt.Errorf("close gVisor evidence collector: %w", err)
	}
	if err := removeOwnedBundle(e.provider.config.BundleRoot, e.bundle); err != nil {
		return err
	}
	e.cleaned = true
	return nil
}

func (e *preparedEnvironment) writeMetadata() error {
	metadata := bundleMetadata{Version: metadataVersion, ContainerID: e.containerID, Phase: metadataPhasePrepared}
	if err := writeJSONFile(filepath.Join(e.bundle, metadataName), metadata); err != nil {
		return fmt.Errorf("write gVisor bundle metadata: %w", err)
	}
	return nil
}

func (e *preparedEnvironment) markRunAttempted() error {
	metadata := bundleMetadata{Version: metadataVersion, ContainerID: e.containerID, Phase: metadataPhaseAttempted}
	return writeJSONFile(filepath.Join(e.bundle, attemptName), metadata)
}

func (p *Provider) runArguments(arguments ...string) []string {
	global := []string{
		"--root=" + p.config.StateRoot,
		"--network=none",
		"--overlay2=none",
		"--directfs=false",
		"--file-access=exclusive",
		"--file-access-mounts=exclusive",
		"--host-uds=none",
		// The only host FIFO reachable from the sandbox is the provider-created,
		// write-only evidence mount. Trusted inputs contain regular files only.
		"--host-fifo=open",
		"--character-device-policy=emulated-only",
		"--net-raw=false",
		"--allow-suid=false",
		"--platform=" + p.config.Platform,
		"--cpu-num-from-quota=true",
	}
	if p.config.CgroupDriver == CgroupDriverSystemdUser {
		global = append(global, "--ignore-cgroups=true")
	}
	return append(global, arguments...)
}

func environmentVariables(values map[string]string) []string {
	merged := map[string]string{
		"HOME":   "/workspace",
		"PATH":   "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TMPDIR": "/tmp",
	}
	for key, value := range values {
		merged[key] = value
	}
	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+merged[key])
	}
	return environment
}

func randomContainerID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "provenance-" + hex.EncodeToString(value), nil
}

func existingDirectory(name, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", name, err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve %s symbolic links: %w", name, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", name, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", name)
	}
	return resolved, nil
}

func ownedDirectory(name, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", name, err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", name, err)
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return "", fmt.Errorf("restrict %s: %w", name, err)
	}
	return existingDirectory(name, absolute)
}

func ensureDescendant(root, candidate string) error {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return err
	}
	if relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("path escapes configured root")
	}
	return nil
}

func pathsOverlap(first, second string) bool {
	return pathContains(first, second) || pathContains(second, first)
}

func pathContains(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func removeOwnedBundle(root, bundle string) error {
	if err := ensureDescendant(root, bundle); err != nil {
		return fmt.Errorf("remove gVisor bundle: %w", err)
	}
	if err := os.RemoveAll(bundle); err != nil {
		return fmt.Errorf("remove gVisor bundle: %w", err)
	}
	return nil
}

func writeJSONFile(path string, value any) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

type command struct {
	Path   string
	Args   []string
	Stdout io.Writer
	Stderr io.Writer
}

type commandResult struct {
	ExitCode *int
	Err      error
}

type commandRunner interface {
	Run(context.Context, command) commandResult
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, invocation command) commandResult {
	process := exec.CommandContext(ctx, invocation.Path, invocation.Args...)
	process.Stdout = invocation.Stdout
	process.Stderr = invocation.Stderr
	err := process.Run()
	var exitCode *int
	if process.ProcessState != nil {
		value := process.ProcessState.ExitCode()
		exitCode = &value
	}
	return commandResult{ExitCode: exitCode, Err: err}
}
