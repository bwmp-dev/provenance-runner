package execution

import (
	"context"
	"errors"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
)

// TestSecretSource is a trusted, ephemeral delivery callback. It must validate
// the current accepted lease and selected references, and clear delivery buffers
// before returning sealed files. Never construct it from job JSON.
type TestSecretSource func(context.Context) (*testsecrets.Files, time.Time, error)

type testSecretSourceKey struct{}

func WithTestSecretSource(ctx context.Context, source TestSecretSource) context.Context {
	return context.WithValue(ctx, testSecretSourceKey{}, source)
}

// TestSecretWorkloadProvider promises that Prepare takes ownership of supplied
// files on every return path. Successful or partial preparation retains ownership
// until sandbox teardown; failed preparation without a delegate closes them.
// ResolveWorkload never takes ownership on failure.
type TestSecretWorkloadProvider interface {
	IsolatedWorkloadProvider
	SupportsTestSecretFiles() bool
}

// AcquireTestSecretFiles is called only after slow artifact preparation. Missing
// sources preserve no-secret behavior. Unsupported sandboxes are refused before
// invoking a callback that might decrypt values.
func AcquireTestSecretFiles(ctx context.Context, sandbox IsolatedWorkloadProvider) (*testsecrets.Files, time.Time, error) {
	source, _ := ctx.Value(testSecretSourceKey{}).(TestSecretSource)
	if source == nil {
		return nil, time.Time{}, nil
	}
	unavailable := func() error {
		return NewClassifiedError(ClassificationInfrastructureFailure, "test_secrets_unavailable", errors.New("test-secret preparation unavailable"))
	}
	supported, ok := sandbox.(TestSecretWorkloadProvider)
	if !ok || !supported.SupportsTestSecretFiles() {
		return nil, time.Time{}, unavailable()
	}
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	files, expiresAt, err := source(ctx)
	if err != nil || files == nil || !expiresAt.After(time.Now()) || ctx.Err() != nil {
		if files != nil {
			_ = files.Close()
		}
		return nil, time.Time{}, unavailable()
	}
	if mounts, err := files.Mounts(); err != nil || len(mounts) == 0 {
		_ = files.Close()
		return nil, time.Time{}, unavailable()
	}
	return files, expiresAt, nil
}
