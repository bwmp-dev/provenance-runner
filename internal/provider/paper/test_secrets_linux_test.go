//go:build linux

package paper

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
)

type secretSandbox struct {
	*fakeSandboxProvider
	mode  string
	files *testsecrets.Files
}

func (s *secretSandbox) SupportsTestSecretFiles() bool { return s.mode != "unsupported" }
func (s *secretSandbox) ResolveWorkload(ctx context.Context, request execution.Request, workload execution.IsolatedWorkload) (execution.Environment, error) {
	s.files = workload.TestSecretFiles
	if s.mode == "resolve-error" {
		return nil, errors.New("synthetic resolution failure")
	}
	if s.mode == "nil-environment" {
		return nil, nil
	}
	if _, err := s.fakeSandboxProvider.ResolveWorkload(ctx, request, workload); err != nil {
		return nil, err
	}
	return &secretSandboxEnvironment{sandbox: s}, nil
}

type secretSandboxEnvironment struct{ sandbox *secretSandbox }

func (*secretSandboxEnvironment) Identity() string { return "synthetic-secret-sandbox" }
func (e *secretSandboxEnvironment) Prepare(context.Context) (execution.PreparedEnvironment, error) {
	if e.sandbox.mode == "prepare-error" {
		_ = e.sandbox.files.Close()
		return nil, errors.New("synthetic preparation failure")
	}
	prepared := &secretPrepared{fakePrepared: &fakePrepared{}, files: e.sandbox.files}
	if e.sandbox.mode == "partial-error" {
		return prepared, errors.New("synthetic partial preparation failure")
	}
	return prepared, nil
}

type secretPrepared struct {
	*fakePrepared
	files *testsecrets.Files
}

func (p *secretPrepared) Cleanup(ctx context.Context) error {
	if err := p.fakePrepared.Cleanup(ctx); err != nil {
		return err
	}
	return p.files.Close()
}

func TestPaperSecretDeliveryIsLazyAndRetainsExactCleanupOwnership(t *testing.T) {
	for _, mode := range []string{"success", "unsupported", "resolve-error", "nil-environment", "prepare-error", "partial-error", "materialize-error"} {
		t.Run(mode, func(t *testing.T) {
			payloads := map[string][]byte{"/paper": []byte("Paper"), "/java": testRuntimeArchive(t, "test-jre"), "/target": []byte("target"), "/probe": []byte("probe")}
			server, requests := artifactServer(t, payloads)
			base := &fakeSandboxProvider{prepared: &fakePrepared{}}
			javaRoot := "test-jre"
			if mode == "materialize-error" {
				javaRoot = "missing-jre"
			}
			provider := testProvider(t, server, base, payloads, javaRoot)
			sandbox := &secretSandbox{fakeSandboxProvider: base, mode: mode}
			provider.config.Sandbox = sandbox
			config := validConfiguration(server.URL, payloads)
			config.Dependencies = nil
			config.TestPlan.RequiredDependencies = nil
			called := 0
			var files *testsecrets.Files
			expiresAt := time.Now().Add(time.Minute)
			ctx := execution.WithTestSecretSource(context.Background(), func(context.Context) (*testsecrets.Files, time.Time, error) {
				called++
				for _, path := range []string{"/paper", "/java", "/target", "/probe", "/prepared-runtime"} {
					if requests.snapshot()[path] != 1 {
						t.Error("secret fetched before all artifacts acquired")
					}
				}
				var err error
				files, err = testsecrets.New([]testsecrets.Input{{Name: "token", Value: []byte("synthetic")}})
				return files, expiresAt, err
			})
			prepared, err := resolveTestEnvironment(t, provider, "secret-paper", config).Prepare(ctx)
			if files != nil {
				defer files.Close()
			}
			if (err == nil) != (mode == "success") || prepared == nil {
				t.Fatal("unexpected preparation disposition")
			}
			if mode == "unsupported" || mode == "materialize-error" {
				if called != 0 {
					t.Fatal("decrypted for unsupported or unprepared workload")
				}
			} else {
				if called != 1 || files == nil {
					t.Fatal("expected one lazy delivery")
				}
				_, mountErr := files.Mounts()
				retained := mode == "success" || mode == "partial-error"
				if (mountErr == nil) != retained {
					t.Fatal("incorrect file ownership on preparation return")
				}
				if retained {
					workload := sandbox.lastWorkload()
					if workload.TestSecretFiles != files || !workload.TestSecretExpiresAt.Equal(expiresAt) {
						t.Fatal("trusted delivery identity changed")
					}
				}
			}
			root := prepared.(*preparedEnvironment).workspace.Root()
			if err := prepared.Cleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if files != nil {
				if _, err := files.Mounts(); err == nil {
					t.Fatal("cleanup retained secret handles")
				}
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cleanup retained workspace")
			}
		})
	}
}
