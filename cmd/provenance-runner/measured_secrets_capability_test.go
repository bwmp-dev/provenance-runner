package main

import (
	"context"
	"testing"
)

func TestMeasuredSecretsRequireBothProvisionedRoutes(t *testing.T) {
	worker := &connectedWorker{adapter: &measuredWorkerAdapter{}, measuredEndpoint: "/run/provenance/control.sock"}
	if worker.SupportsTestSecretSource() {
		t.Fatal("default enabled")
	}
	worker.measuredSecrets = true
	if worker.SupportsTestSecretSource() {
		t.Fatal("missing none provider advertised")
	}
	worker.none = &connectedWorker{}
	if worker.SupportsTestSecretSource() {
		t.Fatal("incapable none provider advertised")
	}
	worker.none.adapter = &measuredWorkerAdapter{}
	if !worker.SupportsTestSecretSource() {
		t.Fatal("both provisioned routes not advertised")
	}
	worker.measuredSecrets = false
	if worker.SupportsTestSecretSource() {
		t.Fatal("none alone enabled measured secrets")
	}
}

func TestMeasuredSecretConfigurationFailsClosed(t *testing.T) {
	for _, values := range []map[string]string{
		{"PROVENANCE_MEASURED_TEST_SECRETS": "true"},
		{"PROVENANCE_MEASURED_TEST_SECRETS": "enabled"},
		{"PROVENANCE_MEASURED_TEST_SECRETS": "enabled", "PROVENANCE_MEASURED_SERVICE_SOCKET": "/run/provenance/control.sock"},
		{"PROVENANCE_MEASURED_TEST_SECRETS": "enabled", "PROVENANCE_MEASURED_NONE_PROVIDER": "isolated"},
	} {
		if registry, err := registryForProvider(context.Background(), "paper", func(key string) string { return values[key] }); err == nil || registry != nil {
			t.Fatal("incomplete secret provisioning accepted")
		}
	}
}
