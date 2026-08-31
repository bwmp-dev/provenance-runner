package execution

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/localjob"
)

func TestExecutorSuccessfulLifecycle(t *testing.T) {
	var phases []string
	var phasesMu sync.Mutex
	record := func(phase string) {
		phasesMu.Lock()
		defer phasesMu.Unlock()
		phases = append(phases, phase)
	}
	prepared := &fakePrepared{
		execute: func(context.Context) (ExecutionOutcome, error) {
			record("execute")
			code := 0
			return ExecutionOutcome{ExitCode: &code}, nil
		},
		collect: func(context.Context) (CollectedOutput, error) {
			record("collect")
			return CollectedOutput{
				Stdout:        "ready\n",
				CapturedBytes: 6,
				ObservedBytes: 6,
				StructuredEvents: []StructuredEvent{{
					Sequence: 1,
					Kind:     "probe.ready",
					Payload:  json.RawMessage(`{"ready":true}`),
				}},
				CompleteLog: &CompleteLog{
					ContentType:       "text/plain; charset=utf-8",
					ContentEncoding:   "gzip",
					SHA256:            "digest",
					UncompressedBytes: 6,
					CompressedBytes:   10,
					Data:              []byte("compressed"),
				},
				EvidenceUsage: EvidenceUsage{
					RawBytesObserved:     6,
					CapturedBytes:        6,
					StructuredEventCount: 1,
					StructuredEventBytes: 14,
					CompleteLogBytes:     6,
					CompressedLogBytes:   10,
				},
			}, nil
		},
		cleanup: func(context.Context) error {
			record("cleanup")
			return nil
		},
	}
	provider := &fakeProvider{
		name: "fake",
		resolve: func(context.Context, Request) (Environment, error) {
			record("resolve")
			return &fakeEnvironment{
				identity: "fake/test",
				prepare: func(context.Context) (PreparedEnvironment, error) {
					record("prepare")
					return prepared, nil
				},
			}, nil
		},
	}

	result := newTestExecutor(t, provider).Execute(context.Background(), validJob())
	if !result.Passed() {
		t.Fatalf("result classification = %q, want passed; failure = %#v", result.Classification, result.Failure)
	}
	if result.Phase != PhaseCompleted {
		t.Fatalf("result phase = %q, want completed", result.Phase)
	}
	if result.Environment == nil || result.Environment.Identity != "fake/test" {
		t.Fatalf("environment = %#v", result.Environment)
	}
	if result.Logs == nil || result.Logs.Stdout != "ready\n" {
		t.Fatalf("logs = %#v", result.Logs)
	}
	if len(result.StructuredEvents) != 1 || result.StructuredEvents[0].Kind != "probe.ready" {
		t.Fatalf("structured events = %#v", result.StructuredEvents)
	}
	if result.CompleteLog == nil || string(result.CompleteLog.Data) != "compressed" {
		t.Fatalf("complete log = %#v", result.CompleteLog)
	}
	if result.Usage.StructuredEventCount != 1 || result.Usage.StructuredEventBytes != 14 || result.Usage.CompressedLogBytes != 10 {
		t.Fatalf("usage = %#v", result.Usage)
	}
	if result.Cleanup == nil || !result.Cleanup.Attempted || !result.Cleanup.Succeeded {
		t.Fatalf("cleanup = %#v", result.Cleanup)
	}
	wantPhases := []string{"resolve", "prepare", "execute", "collect", "cleanup"}
	if len(phases) != len(wantPhases) {
		t.Fatalf("phases = %v, want %v", phases, wantPhases)
	}
	for index := range wantPhases {
		if phases[index] != wantPhases[index] {
			t.Fatalf("phases = %v, want %v", phases, wantPhases)
		}
	}
}

func TestExecutorClassifiesWorkloadFailure(t *testing.T) {
	code := 7
	prepared := &fakePrepared{
		execute: func(context.Context) (ExecutionOutcome, error) {
			return ExecutionOutcome{
				ExitCode: &code,
				Failure:  NewFailure(ClassificationWorkloadFailure, "fixture_failed", "fixture failed"),
			}, nil
		},
	}
	provider := preparedProvider(prepared)

	result := newTestExecutor(t, provider).Execute(context.Background(), validJob())
	if result.Classification != ClassificationWorkloadFailure {
		t.Fatalf("classification = %q, want %q", result.Classification, ClassificationWorkloadFailure)
	}
	if result.Execution == nil || result.Execution.ExitCode == nil || *result.Execution.ExitCode != 7 {
		t.Fatalf("execution = %#v", result.Execution)
	}
	if result.Cleanup == nil || !result.Cleanup.Succeeded {
		t.Fatalf("cleanup = %#v", result.Cleanup)
	}
}

func TestExecutorTimesOutButStillCollectsAndCleansUp(t *testing.T) {
	var collected, cleaned bool
	prepared := &fakePrepared{
		execute: func(ctx context.Context) (ExecutionOutcome, error) {
			<-ctx.Done()
			return ExecutionOutcome{}, ctx.Err()
		},
		collect: func(ctx context.Context) (CollectedOutput, error) {
			if err := ctx.Err(); err != nil {
				t.Fatalf("collection context was already done: %v", err)
			}
			collected = true
			return CollectedOutput{}, nil
		},
		cleanup: func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				t.Fatalf("cleanup context was already done: %v", err)
			}
			cleaned = true
			return nil
		},
	}
	job := validJob()
	job.TimeoutMilliseconds = 10

	result := newTestExecutor(t, preparedProvider(prepared)).Execute(context.Background(), job)
	if result.Classification != ClassificationTimedOut {
		t.Fatalf("classification = %q, want %q; failure = %#v", result.Classification, ClassificationTimedOut, result.Failure)
	}
	if !collected || !cleaned {
		t.Fatalf("collected = %t, cleaned = %t", collected, cleaned)
	}
}

func TestExecutorClassifiesParentCancellation(t *testing.T) {
	prepared := &fakePrepared{
		execute: func(ctx context.Context) (ExecutionOutcome, error) {
			<-ctx.Done()
			return ExecutionOutcome{}, ctx.Err()
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := newTestExecutor(t, preparedProvider(prepared)).Execute(ctx, validJob())
	if result.Classification != ClassificationCancelled {
		t.Fatalf("classification = %q, want %q; failure = %#v", result.Classification, ClassificationCancelled, result.Failure)
	}
}

func TestCleanupFailureDoesNotReplaceWorkloadClassification(t *testing.T) {
	prepared := &fakePrepared{
		execute: func(context.Context) (ExecutionOutcome, error) {
			return ExecutionOutcome{Failure: NewFailure(ClassificationWorkloadFailure, "bad_plugin", "bad plugin")}, nil
		},
		cleanup: func(context.Context) error {
			return errors.New("cleanup broke")
		},
	}

	result := newTestExecutor(t, preparedProvider(prepared)).Execute(context.Background(), validJob())
	if result.Classification != ClassificationWorkloadFailure {
		t.Fatalf("classification = %q, want workload failure", result.Classification)
	}
	if result.Cleanup == nil || result.Cleanup.Succeeded || result.Cleanup.Error != "cleanup broke" {
		t.Fatalf("cleanup = %#v", result.Cleanup)
	}
}

func TestCollectionFailureRemainsVisibleWithWorkloadFailure(t *testing.T) {
	prepared := &fakePrepared{
		execute: func(context.Context) (ExecutionOutcome, error) {
			return ExecutionOutcome{Failure: NewFailure(ClassificationWorkloadFailure, "bad_plugin", "bad plugin")}, nil
		},
		collect: func(context.Context) (CollectedOutput, error) {
			return CollectedOutput{}, errors.New("collection broke")
		},
	}

	result := newTestExecutor(t, preparedProvider(prepared)).Execute(context.Background(), validJob())
	if result.Classification != ClassificationWorkloadFailure {
		t.Fatalf("classification = %q, want workload failure", result.Classification)
	}
	if result.Logs == nil || result.Logs.Error != "collection broke" {
		t.Fatalf("logs = %#v", result.Logs)
	}
}

func TestCleanupFailureClassifiesOtherwisePassingJob(t *testing.T) {
	prepared := &fakePrepared{
		cleanup: func(context.Context) error {
			return errors.New("cleanup broke")
		},
	}

	result := newTestExecutor(t, preparedProvider(prepared)).Execute(context.Background(), validJob())
	if result.Classification != ClassificationInfrastructureFailure || result.Phase != PhaseCleanup {
		t.Fatalf("classification = %q, phase = %q, failure = %#v", result.Classification, result.Phase, result.Failure)
	}
}

func TestPrepareErrorWithResourceStillCleansUp(t *testing.T) {
	cleaned := false
	prepared := &fakePrepared{
		cleanup: func(context.Context) error {
			cleaned = true
			return nil
		},
	}
	provider := &fakeProvider{
		name: "fake",
		resolve: func(context.Context, Request) (Environment, error) {
			return &fakeEnvironment{
				identity: "fake/test",
				prepare: func(context.Context) (PreparedEnvironment, error) {
					return prepared, errors.New("partial preparation failed")
				},
			}, nil
		},
	}

	result := newTestExecutor(t, provider).Execute(context.Background(), validJob())
	if result.Classification != ClassificationInfrastructureFailure || !cleaned {
		t.Fatalf("classification = %q, cleaned = %t", result.Classification, cleaned)
	}
}

func TestRegistryRejectsDuplicateProviders(t *testing.T) {
	provider := &fakeProvider{name: "fake"}
	if _, err := NewRegistry(provider, provider); err == nil {
		t.Fatal("NewRegistry() error = nil")
	}
}

func newTestExecutor(t *testing.T, provider EnvironmentProvider) *Executor {
	t.Helper()
	registry, err := NewRegistry(provider)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	executor, err := NewExecutor(registry, ExecutorOptions{CollectionTimeout: time.Second, CleanupTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}
	return executor
}

func validJob() localjob.Job {
	return localjob.Job{
		SchemaVersion: localjob.SchemaVersion,
		ID:            "job/test",
		Provider:      "fake",
		Environment:   json.RawMessage(`{}`),
	}
}

func preparedProvider(prepared PreparedEnvironment) EnvironmentProvider {
	return &fakeProvider{
		name: "fake",
		resolve: func(context.Context, Request) (Environment, error) {
			return &fakeEnvironment{
				identity: "fake/test",
				prepare: func(context.Context) (PreparedEnvironment, error) {
					return prepared, nil
				},
			}, nil
		},
	}
}

type fakeProvider struct {
	name    string
	resolve func(context.Context, Request) (Environment, error)
}

func (p *fakeProvider) Name() string {
	return p.name
}

func (p *fakeProvider) Resolve(ctx context.Context, request Request) (Environment, error) {
	if p.resolve == nil {
		return nil, errors.New("resolve not configured")
	}
	return p.resolve(ctx, request)
}

type fakeEnvironment struct {
	identity string
	prepare  func(context.Context) (PreparedEnvironment, error)
}

func (e *fakeEnvironment) Identity() string {
	return e.identity
}

func (e *fakeEnvironment) Prepare(ctx context.Context) (PreparedEnvironment, error) {
	return e.prepare(ctx)
}

type fakePrepared struct {
	execute func(context.Context) (ExecutionOutcome, error)
	collect func(context.Context) (CollectedOutput, error)
	cleanup func(context.Context) error
}

func (p *fakePrepared) Execute(ctx context.Context) (ExecutionOutcome, error) {
	if p.execute == nil {
		code := 0
		return ExecutionOutcome{ExitCode: &code}, nil
	}
	return p.execute(ctx)
}

func (p *fakePrepared) Collect(ctx context.Context) (CollectedOutput, error) {
	if p.collect == nil {
		return CollectedOutput{}, nil
	}
	return p.collect(ctx)
}

func (p *fakePrepared) Cleanup(ctx context.Context) error {
	if p.cleanup == nil {
		return nil
	}
	return p.cleanup(ctx)
}
