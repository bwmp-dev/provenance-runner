//go:build linux

package gvisor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	"github.com/bwmp-dev/provenance-runner/internal/workspace"
)

type paperSecretSandbox struct {
	*Provider
	prepared *preparedEnvironment
	inputs   string
}

func (s *paperSecretSandbox) ResolveWorkload(ctx context.Context, request execution.Request, workload execution.IsolatedWorkload) (execution.Environment, error) {
	environment, err := s.Provider.ResolveWorkload(ctx, request, workload)
	if err != nil {
		return nil, err
	}
	s.inputs = workload.InputsPath
	return &paperSecretEnvironment{Environment: environment, sandbox: s}, nil
}

type paperSecretEnvironment struct {
	execution.Environment
	sandbox *paperSecretSandbox
}

func (e *paperSecretEnvironment) Prepare(ctx context.Context) (execution.PreparedEnvironment, error) {
	p, err := e.Environment.Prepare(ctx)
	if p != nil {
		e.sandbox.prepared = p.(*preparedEnvironment)
	}
	return p, err
}

func secretSmokeArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// This composes the real Paper materializer and real sandbox with a synthetic
// Java stand-in. It proves secret injection/redaction/cleanup, not Paper plugin
// compatibility; absence of trusted probe lifecycle events must still fail.
func runPaperSecretCompositionSmoke(t *testing.T, provider *Provider, inputsRoot string) {
	for _, cancelRunning := range []bool{false, true} {
		t.Run(map[bool]string{false: "completion", true: "cancellation"}[cancelRunning], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			script := "#!/bin/sh\nset -eu\ntest \"$(id -u)\" = 65532\ntest -s /run/provenance/test-secrets/token\nif (printf x > /run/provenance/test-secrets/token) 2>/dev/null; then exit 2; fi\ncat /run/provenance/test-secrets/token\necho\necho paper-secret-ready\nprintf '%0512d\\n' 0\n"
			if cancelRunning {
				script += "trap '' TERM\nwhile :; do sleep 1; done\n"
			}
			payloads := map[string][]byte{"paper": []byte("synthetic Paper artifact"), "probe": []byte("synthetic probe artifact"), "target": []byte("synthetic target artifact"), "java": secretSmokeArchive(t, map[string]string{"synthetic-jre/bin/java": script}), "prepared": secretSmokeArchive(t, map[string]string{"cache/patched.jar": "synthetic prepared artifact"})}
			cache, err := artifact.NewCache(t.TempDir(), artifact.CacheOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, data := range payloads {
				_, err := cache.AcquireExact(ctx, artifact.SHA256(data), int64(len(data)), artifact.SourceFunc(func(_ context.Context, w io.Writer) error { _, err := w.Write(data); return err }))
				if err != nil {
					t.Fatal(err)
				}
			}
			pin := func(name, filename string) paper.ArtifactPin {
				return paper.ArtifactPin{URI: "https://example.com/" + name, Filename: filename, SHA256: artifact.SHA256(payloads[name]).String(), SizeBytes: int64(len(payloads[name]))}
			}
			root, err := os.MkdirTemp(inputsRoot, "paper-secret-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(root)
			manager, err := workspace.NewManager(root)
			if err != nil {
				t.Fatal(err)
			}
			sandbox := &paperSecretSandbox{Provider: provider}
			composed, err := paper.New(paper.Config{ArtifactCache: cache, PaperCache: cache, JavaCache: cache, ProbeCache: cache, RuntimeCache: cache, Workspaces: manager, Sandbox: sandbox, ArtifactHosts: []string{"example.com"}, Catalog: paper.Catalog{EnvironmentID: "synthetic-secret-paper", Paper: paper.PaperPin{GameVersion: "1.21.8", Build: 60, Artifact: pin("paper", "paper.jar")}, Java: paper.JavaPin{Distribution: "eclipse-temurin", Version: "21.0.8+9", OS: "linux", Architecture: "amd64", ArchiveRoot: "synthetic-jre", Artifact: pin("java", "java.tar.gz"), MaximumExpandedBytes: 1 << 20}, ProbeVersion: "synthetic", ProbeSourceCommit: "synthetic", Probe: pin("probe", "probe.jar"), PreparedRuntime: paper.ArchivePin{Artifact: pin("prepared", "prepared.tar.gz"), MaximumExpandedBytes: 1 << 20}}})
			if err != nil {
				t.Fatal(err)
			}
			config, err := json.Marshal(map[string]any{"artifactKind": paper.ArtifactKindMinecraftPlugin, "environmentId": "synthetic-secret-paper", "target": pin("target", "target.jar"), "testPlan": map[string]any{"targetPlugin": "SyntheticFixture"}, "memoryBytes": 512 << 20, "cpuMillis": 500, "pids": 64, "diskBytes": 16 << 20, "maxLineBytes": 4096})
			if err != nil {
				t.Fatal(err)
			}
			environment, err := composed.Resolve(ctx, execution.Request{JobID: "paper-secret", Environment: config, Limits: execution.Limits{MaxOutputBytes: 65536}})
			if err != nil {
				t.Fatal(err)
			}
			var files *testsecrets.Files
			calls := 0
			sourceCtx := execution.WithTestSecretSource(ctx, func(context.Context) (*testsecrets.Files, time.Time, error) {
				calls++
				value := []byte("synthetic-paper-composition")
				defer clear(value)
				var err error
				files, err = testsecrets.New([]testsecrets.Input{{Name: "token", Value: value}})
				return files, time.Now().Add(time.Minute), err
			})
			var done chan error
			prepared, err := environment.Prepare(sourceCtx)
			if prepared != nil {
				defer func() {
					cancel()
					if done != nil {
						select {
						case <-done:
						case <-time.After(20 * time.Second):
							t.Error("Paper fixture did not stop before teardown")
						}
					}
					cleanupCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
					defer stop()
					if err := prepared.Cleanup(cleanupCtx); err != nil {
						t.Error("Paper secret cleanup failed:", err)
					}
				}()
			}
			if err != nil {
				t.Fatal("Paper secret preparation failed:", err)
			}
			if calls != 1 || files == nil || sandbox.prepared == nil {
				t.Fatal("trusted source was not composed")
			}
			live := &secretSmokeObserver{}
			prepared.(execution.ObserverAttacher).AttachObserver(live)
			done = make(chan error, 1)
			go func() {
				defer close(done)
				outcome, err := prepared.Execute(ctx)
				if err == nil && (outcome.ExitCode == nil || *outcome.ExitCode != 0) {
					err = errors.New("synthetic Java stand-in failed")
				}
				done <- err
			}()
			if cancelRunning {
				deadline := time.Now().Add(10 * time.Second)
				for !strings.Contains(live.text(), "paper-secret-ready") {
					select {
					case err := <-done:
						t.Fatal("Paper secret guest exited before readiness:", err)
					default:
					}
					if time.Now().After(deadline) {
						t.Fatal("Paper secret guest not ready")
					}
					time.Sleep(25 * time.Millisecond)
				}
				cancel()
			}
			select {
			case err := <-done:
				if cancelRunning {
					if !errors.Is(err, context.Canceled) {
						t.Fatal("Paper secret cancellation failed:", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("Paper secret guest did not stop")
			}
			output, collectErr := prepared.Collect(context.Background())
			if collectErr == nil {
				t.Fatal("synthetic stand-in incorrectly passed Paper lifecycle validation")
			}
			if !strings.Contains(output.Stdout, "[REDACTED]") || strings.Contains(output.Stdout, "synthetic-paper-composition") || strings.Contains(live.text(), "synthetic-paper-composition") {
				t.Fatal("composed Paper output not redacted")
			}
			if output.CompleteLog == nil || output.CompleteLog.Archive == nil {
				t.Fatal("composed complete log missing")
			}
			defer output.CompleteLog.Archive.Close()
			archive, err := gzip.NewReader(io.NewSectionReader(output.CompleteLog.Archive, 0, output.CompleteLog.CompressedBytes))
			if err != nil {
				t.Fatal("composed complete log framing failed")
			}
			complete, readErr := io.ReadAll(io.LimitReader(archive, 65537))
			archive.Close()
			if readErr != nil || len(complete) > 65536 || !bytes.Contains(complete, []byte("paper-secret-ready")) || bytes.Contains(complete, []byte("synthetic-paper-composition")) {
				t.Fatal("composed stored log not redacted")
			}
			cleanupCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			if err := prepared.Cleanup(cleanupCtx); err != nil {
				t.Fatal(err)
			}
			if _, err := files.Mounts(); err == nil {
				t.Fatal("Paper cleanup retained secret files")
			}
			assertNoSandboxResidue(t, provider, sandbox.prepared.containerID)
			if _, err := os.Stat(filepath.Join(provider.secretTmpfsRoot(), sandbox.prepared.containerID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("Paper cleanup retained secret tmpfs")
			}
			if _, err := os.Stat(sandbox.inputs); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("Paper cleanup retained workspace")
			}
		})
	}
}
