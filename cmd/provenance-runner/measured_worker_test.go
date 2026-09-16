package main

import (
	"context"
	"errors"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

type measuredWorkerAdapter struct {
	calls       int
	failCleanup bool
}

func (a *measuredWorkerAdapter) AdaptJob(*p.JobSpecification) (localjob.Job, error) {
	return localjob.Job{}, errors.New("legacy adaptation forbidden")
}
func (a *measuredWorkerAdapter) SupportsTestSecretSource() bool { return true }
func (a *measuredWorkerAdapter) ExecuteMeasured(_ context.Context, _ *p.JobSpecification, endpoint string, _ func(context.Context, execution.ExecutionStart) error) execution.Result {
	a.calls++
	if endpoint != "/run/provenance/control.sock" {
		panic("endpoint changed")
	}
	return execution.Result{Cleanup: &execution.CleanupResult{Attempted: true, Succeeded: !a.failCleanup}}
}

func TestMeasuredConnectedWorkerNoFallbackOrCapacityReuse(t *testing.T) {
	adapter := &measuredWorkerAdapter{failCleanup: true}
	worker := &connectedWorker{adapter: adapter, measuredEndpoint: "/run/provenance/control.sock"}
	if worker.SupportsTestSecretSource() {
		t.Fatal("unimplemented measured secrets advertised")
	}
	if result := worker.Execute(context.Background(), nil, nil); result.Failure == nil || adapter.calls != 0 {
		t.Fatal("legacy execution admitted")
	}
	worker.admission.Lock()
	if result := worker.ExecuteV2(context.Background(), nil, nil); result.Failure == nil || adapter.calls != 0 {
		t.Fatal("concurrent session admitted")
	}
	worker.admission.Unlock()
	result := worker.ExecuteV2(context.Background(), nil, nil)
	if result.Cleanup == nil || result.Cleanup.Succeeded || adapter.calls != 1 {
		t.Fatal("failed cleanup lost")
	}
	if result := worker.ExecuteV2(context.Background(), nil, nil); result.Failure == nil || adapter.calls != 1 {
		t.Fatal("capacity reused after failed cleanup")
	}
}

func TestMeasuredEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{"relative", "/run/../control.sock", "/run/control\x00.sock"} {
		_, err := registryForProvider(context.Background(), "paper", func(name string) string {
			if name == "PROVENANCE_MEASURED_SERVICE_SOCKET" {
				return endpoint
			}
			return ""
		})
		if err == nil {
			t.Fatal("invalid endpoint admitted")
		}
	}
}
