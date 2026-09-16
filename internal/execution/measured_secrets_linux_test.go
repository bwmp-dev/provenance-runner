//go:build linux

package execution

import (
	"context"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

func TestMeasuredSecretsCannotDecryptWithoutSealedRootObservation(t *testing.T) {
	called := false
	ctx := WithTestSecretSource(context.Background(), func(context.Context) (*ts.Files, time.Time, error) { called = true; return nil, time.Time{}, nil })
	job := &p.JobSpecification{NormalizedConfigurationJson: []byte(`{"tests":{"secrets":{"license":1}}}`), TestSecrets: []*p.TestSecretReference{{Name: "license", SecretId: "b1111111-1111-4111-8111-111111111111", Version: 1}}}
	for _, observation := range []*runtimeidentity.NetworkObservation{nil, {}} {
		files, expires, err := AcquireMeasuredTestSecretFiles(ctx, job, observation)
		if err == nil || files != nil || !expires.IsZero() || called {
			t.Fatal("decrypted without an authenticated exact-job observation")
		}
	}
	if files, _, err := AcquireMeasuredTestSecretFiles(nil, job, nil); err == nil || files != nil {
		t.Fatal("nil context")
	}
	if files, _, err := AcquireMeasuredTestSecretFiles(ctx, nil, nil); err == nil || files != nil {
		t.Fatal("nil job")
	}
	if called {
		t.Fatal("source invoked")
	}
}
