package main

import (
	"context"
	"errors"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

type noneV2Adapter struct {
	calls  int
	legacy int
}

func (a *noneV2Adapter) AdaptJob(*p.JobSpecification) (localjob.Job, error) {
	a.legacy++
	return localjob.Job{}, errors.New("legacy refused")
}
func (a *noneV2Adapter) AdaptNoNetworkV2(*p.JobSpecification) (localjob.Job, error) {
	a.calls++
	return localjob.Job{}, errors.New("synthetic stop before execution")
}

func TestNoneV2DispatchIsExplicitAndNeverNetworkFailureFallback(t *testing.T) {
	root := &measuredWorkerAdapter{}
	none := &noneV2Adapter{}
	worker := &connectedWorker{adapter: root, measuredEndpoint: "/run/provenance/control.sock", none: &connectedWorker{adapter: none}}
	job := &p.JobSpecification{EffectivePolicy: &p.EffectivePolicy{NetworkV2: &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_NONE}}}
	if result := worker.ExecuteV2(context.Background(), job, nil); result.Failure == nil || none.calls != 1 || none.legacy != 0 || root.calls != 0 {
		t.Fatal("none dispatch changed wire admission or called root")
	}
	job.EffectivePolicy.NetworkV2.Mode = p.NetworkMode_NETWORK_MODE_ALLOWLIST
	root.failCleanup = true
	result := worker.ExecuteV2(context.Background(), job, nil)
	if result.Cleanup == nil || result.Cleanup.Succeeded || root.calls != 1 || none.calls != 1 {
		t.Fatal("network failure fell back to none")
	}
	job.EffectivePolicy.NetworkV2.Mode = p.NetworkMode_NETWORK_MODE_NONE
	if result := worker.ExecuteV2(context.Background(), job, nil); result.Failure == nil || none.calls != 1 {
		t.Fatal("none capacity reused after root cleanup failure")
	}
}

func TestNoneV2NeedsProvisionedProviderAndStillSharesAdmission(t *testing.T) {
	root := &measuredWorkerAdapter{}
	worker := &connectedWorker{adapter: root, measuredEndpoint: "/run/provenance/control.sock"}
	job := &p.JobSpecification{EffectivePolicy: &p.EffectivePolicy{NetworkV2: &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_NONE}}}
	if result := worker.ExecuteV2(context.Background(), job, nil); result.Failure == nil || root.calls != 0 {
		t.Fatal("unprovisioned none accepted")
	}
	none := &noneV2Adapter{}
	worker.none = &connectedWorker{adapter: none}
	worker.admission.Lock()
	if result := worker.ExecuteV2(context.Background(), job, nil); result.Failure == nil || none.calls != 0 {
		t.Fatal("none bypassed global admission")
	}
	worker.admission.Unlock()
	if result := worker.Execute(context.Background(), job, nil); result.Failure == nil || none.calls != 0 || root.calls != 0 {
		t.Fatal("v1 entered explicit v2 path")
	}
}

func TestNoneProviderConfigurationIsClosed(t *testing.T) {
	for _, mode := range []string{"true", "legacy", "arbitrary", "isolated"} {
		_, err := registryForProvider(context.Background(), "paper", func(name string) string {
			if name == "PROVENANCE_MEASURED_NONE_PROVIDER" {
				return mode
			}
			return ""
		})
		if err == nil {
			t.Fatal("invalid/unbound none provider option")
		}
	}
}
