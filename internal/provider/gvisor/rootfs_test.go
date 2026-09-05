package gvisor

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

func TestValidateRootFSRequiresPreprovisionedReadOnlyMountTargets(t *testing.T) {
	rootFS := preparedRootFSFixture(t)
	sourceRoot := t.TempDir()
	runtimeSource := filepath.Join(sourceRoot, "runtime")
	fileSource := filepath.Join(sourceRoot, "dependency.jar")
	if err := os.Mkdir(runtimeSource, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileSource, []byte("dependency"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rootFS, "workspace", "plugins"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootFS, "workspace", "plugins", "dependency.jar"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	var checked []string
	readOnly := func(path string) error {
		checked = append(checked, path)
		return nil
	}
	mounts := []execution.ReadOnlyMount{
		{Source: runtimeSource, Destination: "/runtime", Executable: true},
		{Source: fileSource, Destination: "/workspace/plugins/dependency.jar"},
	}
	eventFile := &execution.StructuredEventFile{Destination: "/tmp/provenance-probe-events.ndjson", Kind: "probe", MaximumBytes: 1024}
	if err := validateRootFS(rootFS, mounts, eventFile, readOnly); err != nil {
		t.Fatalf("validateRootFS() error = %v", err)
	}
	for _, expected := range []string{
		rootFS,
		filepath.Join(rootFS, "proc"),
		filepath.Join(rootFS, "dev"),
		filepath.Join(rootFS, "dev", "pts"),
		filepath.Join(rootFS, "workspace"),
		filepath.Join(rootFS, "tmp"),
		filepath.Join(rootFS, "inputs"),
		filepath.Join(rootFS, "runtime"),
		filepath.Join(rootFS, "workspace", "plugins", "dependency.jar"),
		filepath.Join(rootFS, "tmp", "provenance-probe-events.ndjson"),
	} {
		if !slices.Contains(checked, expected) {
			t.Errorf("read-only check omitted %q; checked = %#v", expected, checked)
		}
	}
}

func TestValidateRootFSRejectsUnsafeMountTargets(t *testing.T) {
	newSource := func(t *testing.T, directory bool) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "source")
		var err error
		if directory {
			err = os.Mkdir(path, 0o700)
		} else {
			err = os.WriteFile(path, nil, 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	readOnly := func(string) error { return nil }

	tests := map[string]struct {
		prepare     func(*testing.T, string)
		mounts      []execution.ReadOnlyMount
		eventFile   *execution.StructuredEventFile
		wantMessage string
	}{
		"unsafe root mode": {
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(root, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			wantMessage: "root filesystem mode",
		},
		"missing fixed destination": {
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "inputs")); err != nil {
					t.Fatal(err)
				}
			},
			wantMessage: `mount target "/inputs" is missing`,
		},
		"symlink ancestor": {
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "workspace")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), filepath.Join(root, "workspace")); err != nil {
					t.Fatal(err)
				}
			},
			wantMessage: "contains symbolic link",
		},
		"escaping destination": {
			mounts:      []execution.ReadOnlyMount{{Source: newSource(t, true), Destination: "/runtime/../../etc"}},
			wantMessage: "must be a clean absolute container path",
		},
		"directory source onto file": {
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "runtime")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "runtime"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			mounts:      []execution.ReadOnlyMount{{Source: newSource(t, true), Destination: "/runtime"}},
			wantMessage: `mount target "/runtime" must be a directory`,
		},
		"file source onto directory": {
			prepare: func(t *testing.T, root string) {
				t.Helper()
			},
			mounts:      []execution.ReadOnlyMount{{Source: newSource(t, false), Destination: "/runtime"}},
			wantMessage: `mount target "/runtime" has conflicting type or mode requirements`,
		},
		"event destination is directory": {
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "tmp", "provenance-probe-events.ndjson")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(root, "tmp", "provenance-probe-events.ndjson"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			eventFile:   &execution.StructuredEventFile{Destination: "/tmp/provenance-probe-events.ndjson"},
			wantMessage: `mount target "/tmp/provenance-probe-events.ndjson" must be a regular file`,
		},
		"event destination is nonempty": {
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, "tmp", "provenance-probe-events.ndjson"), []byte("stale"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			eventFile:   &execution.StructuredEventFile{Destination: "/tmp/provenance-probe-events.ndjson"},
			wantMessage: `mount target "/tmp/provenance-probe-events.ndjson" must be empty`,
		},
		"unsafe directory mode": {
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(root, "runtime"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			wantMessage: `mount target "/runtime" mode`,
		},
		"non-traversable workspace": {
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(root, "workspace"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			wantMessage: `mount target "/workspace" mode`,
		},
		"writable nested mount": {
			prepare: func(t *testing.T, root string) {
				t.Helper()
			},
			mounts:      []execution.ReadOnlyMount{{Source: newSource(t, true), Destination: "/runtime"}},
			wantMessage: `mount target "/runtime" is not on a read-only mount`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rootFS := preparedRootFSFixture(t)
			if test.prepare != nil {
				test.prepare(t, rootFS)
			}
			check := readOnly
			if name == "writable nested mount" {
				check = func(path string) error {
					if path == filepath.Join(rootFS, "runtime") {
						return errors.New("filesystem is writable")
					}
					return nil
				}
			}
			err := validateRootFS(rootFS, test.mounts, test.eventFile, check)
			if err == nil || !strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("validateRootFS() error = %v, want containing %q", err, test.wantMessage)
			}
		})
	}
}

func TestValidateImmutableRootFSRejectsWritableFilesystem(t *testing.T) {
	rootFS := preparedRootFSFixture(t)
	err := validateImmutableRootFS(rootFS, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "must be mounted read-only") || !strings.Contains(err.Error(), "filesystem is writable") {
		t.Fatalf("validateImmutableRootFS() error = %v", err)
	}
}

func TestPrepareAndExecuteFailClosedWhenRootFSValidationChanges(t *testing.T) {
	provider, runner, _ := testProvider(t)
	var validations int
	provider.validateRootFSLayout = func(string, []execution.ReadOnlyMount, *execution.StructuredEventFile) error {
		validations++
		if validations == 2 {
			return errors.New("root filesystem became writable")
		}
		return nil
	}
	prepared := prepareEnvironment(t, provider, validConfiguration(), 1024)
	t.Cleanup(func() { _ = prepared.Cleanup(t.Context()) })

	_, err := prepared.Execute(t.Context())
	if err == nil || !strings.Contains(err.Error(), "gvisor_rootfs_invalid") || !strings.Contains(err.Error(), "became writable") {
		t.Fatalf("Execute() error = %v", err)
	}
	if commands := runner.commands(); len(commands) != 0 {
		t.Fatalf("runtime invoked after root filesystem validation failure: %#v", commands)
	}
}

func preparedRootFSFixture(t *testing.T) string {
	t.Helper()
	rootFS := t.TempDir()
	if err := os.Chmod(rootFS, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"proc", "dev", "dev/pts"} {
		if err := os.MkdirAll(filepath.Join(rootFS, filepath.FromSlash(target)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"inputs", "runtime"} {
		if err := os.Mkdir(filepath.Join(rootFS, target), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(rootFS, "workspace"), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rootFS, "tmp"), os.ModeSticky|0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootFS, "tmp", "provenance-probe-events.ndjson"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return rootFS
}
