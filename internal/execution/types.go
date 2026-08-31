package execution

import (
	"context"
	"encoding/json"
	"fmt"
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

type Environment interface {
	Identity() string
	// Prepare must return ownership of partially allocated resources with its error,
	// or release them before returning a nil PreparedEnvironment.
	Prepare(context.Context) (PreparedEnvironment, error)
}

type PreparedEnvironment interface {
	Execute(context.Context) (ExecutionOutcome, error)
	Collect(context.Context) (CollectedOutput, error)
	Cleanup(context.Context) error
}

type ExecutionOutcome struct {
	ExitCode *int
	Failure  *Failure
}

type CollectedOutput struct {
	Stdout          string
	Stderr          string
	CapturedBytes   int64
	ObservedBytes   int64
	OutputTruncated bool
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
	SchemaVersion  string             `json:"schemaVersion"`
	JobID          string             `json:"jobId,omitempty"`
	Status         string             `json:"status"`
	Classification Classification     `json:"classification"`
	Phase          Phase              `json:"phase"`
	Environment    *EnvironmentResult `json:"environment,omitempty"`
	Execution      *ExecutionResult   `json:"execution,omitempty"`
	Logs           *LogsResult        `json:"logs,omitempty"`
	Cleanup        *CleanupResult     `json:"cleanup,omitempty"`
	Usage          UsageResult        `json:"usage"`
	Failure        *Failure           `json:"failure,omitempty"`
	StartedAt      time.Time          `json:"startedAt"`
	CompletedAt    time.Time          `json:"completedAt"`
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
	WallTimeMilliseconds int64 `json:"wallTimeMilliseconds"`
}

func (r Result) Passed() bool {
	return r.Classification == ClassificationPassed
}
