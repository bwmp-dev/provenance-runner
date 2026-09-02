package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const ResultSchemaVersion = "provenance.local-result/v1alpha1"

type Classification string

const (
	ClassificationPassed                Classification = "passed"
	ClassificationInvalidJob            Classification = "invalid_job"
	ClassificationWorkloadFailure       Classification = "workload_failure"
	ClassificationInfrastructureFailure Classification = "infrastructure_failure"
	ClassificationTimedOut              Classification = "timed_out"
	ClassificationCancelled             Classification = "cancelled"
)

type Phase string

const (
	PhaseValidation  Phase = "validation"
	PhaseResolution  Phase = "resolution"
	PhasePreparation Phase = "preparation"
	PhaseExecution   Phase = "execution"
	PhaseCollection  Phase = "collection"
	PhaseCleanup     Phase = "cleanup"
	PhaseCompleted   Phase = "completed"
)

type Request struct {
	JobID       string
	Environment json.RawMessage
	Limits      Limits
}

type Limits struct {
	MaxOutputBytes int64
}

type EnvironmentProvider interface {
	Name() string
	Resolve(context.Context, Request) (Environment, error)
}

// IsolatedWorkloadProvider is the trusted composition boundary between a
// product environment and its sandbox. Job JSON cannot select host paths or
// read-only mounts directly.
type IsolatedWorkloadProvider interface {
	Identity() string
	ResolveWorkload(context.Context, Request, IsolatedWorkload) (Environment, error)
}

type IsolatedWorkload struct {
	Command                string
	Arguments              []string
	Environment            map[string]string
	InputsPath             string
	ReadOnlyMounts         []ReadOnlyMount
	Network                string
	MemoryBytes            int64
	CPUMillis              int64
	PIDs                   int64
	DiskBytes              int64
	MaxLineBytes           int64
	RedactSecrets          []string
	StructuredOutputPrefix string
	StructuredOutputKind   string
	StructuredEventFile    *StructuredEventFile
}

// StructuredEventFile requests a bounded host-backed NDJSON channel created by
// the sandbox provider before execution. Only a trusted product provider can
// select the destination and event kind. The file preserves flushed events
// across abnormal sandbox teardown, but it does not authenticate which process
// inside the sandbox wrote them; consumers must validate the complete protocol.
type StructuredEventFile struct {
	Destination  string
	Kind         string
	MaximumBytes int64
}

type ReadOnlyMount struct {
	Source      string
	Destination string
	Executable  bool
}

type Environment interface {
	Identity() string
	// Prepare must return ownership of partially allocated resources with its error,
	// or release them before returning a nil PreparedEnvironment.
	Prepare(context.Context) (PreparedEnvironment, error)
}

// ResourceClassReporter exposes the allocation applied to an isolated
// environment. It is optional so development providers without a resource
// boundary do not misrepresent host execution as constrained.
type ResourceClassReporter interface {
	ResourceClass() ResourceClass
}

type ResourceClass struct {
	CPUMillis                      int64  `json:"cpuMillis"`
	MemoryBytes                    int64  `json:"memoryBytes"`
	ProcessCount                   int64  `json:"processCount"`
	DiskBytes                      int64  `json:"diskBytes"`
	Network                        string `json:"network"`
	MaximumConnections             int64  `json:"maximumConnections"`
	MaximumBandwidthBytesPerSecond int64  `json:"maximumBandwidthBytesPerSecond"`
}

type PreparedEnvironment interface {
	Execute(context.Context) (ExecutionOutcome, error)
	Collect(context.Context) (CollectedOutput, error)
	Cleanup(context.Context) error
}

// ExecutionObserver receives already-sanitized live evidence and measurements
// taken by the provider. Implementations must return immediately: workload
// output and sandbox execution are never backpressured by a remote consumer.
type ExecutionObserver interface {
	ObserveLog(LiveLogEntry)
	ObserveUsage(ResourceUsage)
}

// ObserverAttacher is optional. Providers implement it when they can expose
// their sanitized evidence stream and measured resource counters.
type ObserverAttacher interface {
	AttachObserver(ExecutionObserver)
}

type LiveLogEntry struct {
	Stream   string
	Data     []byte
	Partial  bool
	Redacted bool
}

// ResourceUsage contains cumulative measurements only. A zero field means the
// provider cannot measure that dimension; callers must not derive a substitute.
type ResourceUsage struct {
	CPUTime              time.Duration
	PeakMemoryBytes      uint64
	DiskReadBytes        uint64
	DiskWriteBytes       uint64
	NetworkReceiveBytes  uint64
	NetworkTransmitBytes uint64
}

type ExecutionOutcome struct {
	ExitCode *int
	Failure  *Failure
}

type CollectedOutput struct {
	Stdout               string
	Stderr               string
	CapturedBytes        int64
	ObservedBytes        int64
	OutputTruncated      bool
	StructuredEvents     []StructuredEvent
	CompleteLog          *CompleteLog
	EvidenceUsage        EvidenceUsage
	StructuredEventError string
	ResourceUsage        *ResourceUsage
}

type StructuredEvent struct {
	Sequence uint64          `json:"sequence"`
	Kind     string          `json:"kind"`
	Payload  json.RawMessage `json:"payload"`
}

type CompleteLog struct {
	State             string   `json:"state"`
	Truncated         bool     `json:"truncated"`
	Error             string   `json:"error,omitempty"`
	ContentType       string   `json:"contentType"`
	ContentEncoding   string   `json:"contentEncoding"`
	SHA256            string   `json:"sha256"`
	UncompressedBytes int64    `json:"uncompressedBytes"`
	CompressedBytes   int64    `json:"compressedBytes"`
	Archive           *os.File `json:"-"`
}

type EvidenceUsage struct {
	RawBytesObserved     int64
	CapturedBytes        int64
	StructuredEventCount int64
	StructuredEventBytes int64
	CompleteLogBytes     int64
	CompressedLogBytes   int64
	TruncatedLineCount   int64
	OutputTruncated      bool
	CompleteLogState     string
	CompleteLogTruncated bool
	EventsTruncated      bool
}

type Failure struct {
	Classification Classification `json:"classification"`
	Code           string         `json:"code"`
	Message        string         `json:"message"`
}

func NewFailure(classification Classification, code, message string) *Failure {
	return &Failure{Classification: classification, Code: code, Message: message}
}

type classifiedError struct {
	failure Failure
	err     error
}

func (e *classifiedError) Error() string {
	return fmt.Sprintf("%s: %v", e.failure.Code, e.err)
}

func (e *classifiedError) Unwrap() error {
	return e.err
}

func NewClassifiedError(classification Classification, code string, err error) error {
	if err == nil {
		return nil
	}
	return &classifiedError{
		failure: Failure{Classification: classification, Code: code, Message: err.Error()},
		err:     err,
	}
}

type Result struct {
	SchemaVersion    string             `json:"schemaVersion"`
	JobID            string             `json:"jobId,omitempty"`
	Status           string             `json:"status"`
	Classification   Classification     `json:"classification"`
	Phase            Phase              `json:"phase"`
	Environment      *EnvironmentResult `json:"environment,omitempty"`
	Execution        *ExecutionResult   `json:"execution,omitempty"`
	Logs             *LogsResult        `json:"logs,omitempty"`
	StructuredEvents []StructuredEvent  `json:"structuredEvents,omitempty"`
	CompleteLog      *CompleteLog       `json:"completeLog,omitempty"`
	Cleanup          *CleanupResult     `json:"cleanup,omitempty"`
	Usage            UsageResult        `json:"usage"`
	Failure          *Failure           `json:"failure,omitempty"`
	StartedAt        time.Time          `json:"startedAt"`
	CompletedAt      time.Time          `json:"completedAt"`
}

type EnvironmentResult struct {
	Provider string `json:"provider"`
	Identity string `json:"identity"`
}

type ExecutionResult struct {
	ExitCode *int `json:"exitCode,omitempty"`
}

type LogsResult struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	CapturedBytes   int64  `json:"capturedBytes"`
	ObservedBytes   int64  `json:"observedBytes"`
	OutputTruncated bool   `json:"outputTruncated"`
	Error           string `json:"error,omitempty"`
}

type CleanupResult struct {
	Attempted            bool   `json:"attempted"`
	Succeeded            bool   `json:"succeeded"`
	DurationMilliseconds int64  `json:"durationMilliseconds"`
	Error                string `json:"error,omitempty"`
}

type UsageResult struct {
	ResourceClass             *ResourceClass `json:"resourceClass,omitempty"`
	WallTimeMilliseconds      int64          `json:"wallTimeMilliseconds"`
	RawOutputBytes            int64          `json:"rawOutputBytes,omitempty"`
	CapturedOutputBytes       int64          `json:"capturedOutputBytes,omitempty"`
	StructuredEventCount      int64          `json:"structuredEventCount,omitempty"`
	StructuredEventBytes      int64          `json:"structuredEventBytes,omitempty"`
	CompleteLogBytes          int64          `json:"completeLogBytes,omitempty"`
	CompressedLogBytes        int64          `json:"compressedLogBytes,omitempty"`
	TruncatedLineCount        int64          `json:"truncatedLineCount,omitempty"`
	OutputTruncated           bool           `json:"outputTruncated,omitempty"`
	CompleteLogState          string         `json:"completeLogState,omitempty"`
	CompleteLogTruncated      bool           `json:"completeLogTruncated,omitempty"`
	StructuredEventsTruncated bool           `json:"structuredEventsTruncated,omitempty"`
	MeasuredResources         *ResourceUsage `json:"measuredResources,omitempty"`
}

func (r Result) Passed() bool {
	return r.Classification == ClassificationPassed
}
