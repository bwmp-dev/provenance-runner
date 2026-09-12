//go:build linux

package execution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
)

type secretTestSandbox struct{ supported bool }

func (secretTestSandbox) Identity() string { return "synthetic" }
func (secretTestSandbox) ResolveWorkload(context.Context, Request, IsolatedWorkload) (Environment, error) {
	panic("not used")
}
func (s secretTestSandbox) SupportsTestSecretFiles() bool { return s.supported }

func TestAcquireSecretsDoesNotDecryptForUnsupportedSandboxOrCancellation(t *testing.T) {
	called := false
	source := TestSecretSource(func(context.Context) (*testsecrets.Files, time.Time, error) {
		called = true
		return nil, time.Time{}, nil
	})
	ctx := WithTestSecretSource(context.Background(), source)
	for _, sandbox := range []IsolatedWorkloadProvider{nil, secretTestSandbox{}} {
		if _, _, err := AcquireTestSecretFiles(ctx, sandbox); err == nil {
			t.Fatal("unsupported sandbox accepted")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := AcquireTestSecretFiles(cancelled, secretTestSandbox{true}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled source invoked")
	}
	if called {
		t.Fatal("source invoked before sandbox/cancellation checks")
	}
	if files, expiry, err := AcquireTestSecretFiles(context.Background(), nil); files != nil || !expiry.IsZero() || err != nil {
		t.Fatal("no-secret behavior changed")
	}
}

func TestAcquireSecretsValidatesAndClosesRejectedFiles(t *testing.T) {
	for _, mode := range []string{"success", "expired", "missing-expiry", "error", "cancelled", "closed"} {
		t.Run(mode, func(t *testing.T) {
			files, err := testsecrets.New([]testsecrets.Input{{Name: "token", Value: []byte("synthetic")}})
			if err != nil {
				t.Fatal(err)
			}
			defer files.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			expiresAt := time.Now().Add(time.Minute)
			source := TestSecretSource(func(context.Context) (*testsecrets.Files, time.Time, error) {
				switch mode {
				case "expired":
					expiresAt = time.Now().Add(-time.Second)
				case "missing-expiry":
					expiresAt = time.Time{}
				case "error":
					return files, expiresAt, errors.New("synthetic sensitive failure")
				case "cancelled":
					cancel()
				case "closed":
					_ = files.Close()
				}
				return files, expiresAt, nil
			})
			got, expiry, err := AcquireTestSecretFiles(WithTestSecretSource(ctx, source), secretTestSandbox{true})
			if mode == "success" {
				if got != files || !expiry.Equal(expiresAt) || err != nil {
					t.Fatal("valid source not transferred")
				}
				if _, err := files.Mounts(); err != nil {
					t.Fatal("valid files prematurely closed")
				}
			} else {
				if got != nil || !expiry.IsZero() || err == nil || strings.Contains(err.Error(), "synthetic") {
					t.Fatal("source failure was not safely refused")
				}
				if _, err := files.Mounts(); err == nil {
					t.Fatal("rejected files retained")
				}
			}
		})
	}
}
