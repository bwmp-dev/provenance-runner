package main

import (
	"context"
	"testing"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

func TestMeasuredNetworkMaximumIsExplicitAndCopied(t *testing.T) {
	worker := &connectedWorker{}
	if worker.MeasuredNetworkMaximum() != nil {
		t.Fatal("unprovisioned maximum")
	}
	worker.measuredEndpoint = "/run/provenance/control.sock"
	worker.measuredMaximum = &p.EffectivePolicy{NetworkV2: &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_NONE}}
	if worker.MeasuredNetworkMaximum() != nil {
		t.Fatal("missing none route")
	}
	worker.none = &connectedWorker{}
	copy := worker.MeasuredNetworkMaximum()
	copy.NetworkV2.Mode = p.NetworkMode_NETWORK_MODE_UNRESTRICTED
	if worker.MeasuredNetworkMaximum().NetworkV2.Mode != p.NetworkMode_NETWORK_MODE_NONE {
		t.Fatal("mutable maximum escaped")
	}
	for _, values := range []map[string]string{
		{"PROVENANCE_MEASURED_NETWORK_V2": "true"},
		{"PROVENANCE_MEASURED_NETWORK_V2": "enabled"},
		{"PROVENANCE_MEASURED_NETWORK_V2": "enabled", "PROVENANCE_MEASURED_SERVICE_SOCKET": "/run/provenance/control.sock"},
		{"PROVENANCE_MEASURED_NETWORK_V2": "enabled", "PROVENANCE_MEASURED_NONE_PROVIDER": "isolated"},
	} {
		if registry, err := registryForProvider(context.Background(), "paper", func(key string) string { return values[key] }); registry != nil || err == nil {
			t.Fatal("incomplete network configuration accepted")
		}
	}
}

func TestMeasuredWorkerRetainsLegacyNoneWithV2Evidence(t *testing.T) {
	root, none := &measuredWorkerAdapter{}, &noneV2Adapter{}
	worker := &connectedWorker{adapter: root, measuredEndpoint: "/run/provenance/control.sock", none: &connectedWorker{adapter: none}}
	job := &p.JobSpecification{EffectivePolicy: &p.EffectivePolicy{Network: &p.NetworkPolicy{Mode: p.NetworkMode_NETWORK_MODE_NONE}}}
	worker.ExecuteV2(context.Background(), job, nil)
	if root.calls != 0 || none.legacy != 1 || none.calls != 0 {
		t.Fatal("legacy none changed policy or entered root route")
	}
	worker.Execute(context.Background(), job, nil)
	if root.calls != 0 || none.legacy != 1 {
		t.Fatal("v1 execution entered measured dispatch")
	}
}
