package paper

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func guestPreparationFixture(t *testing.T) (measuredGuestConfiguration, string, string) {
	t.Helper()
	inputRoot, workRoot := t.TempDir(), t.TempDir()
	probe, _ := json.Marshal(testPlan{TargetPlugin: "Fixture", StabilizationMilliseconds: 1000, Console: []consoleCommandTest{}})
	values := []struct {
		name string
		data []byte
	}{{"java.tar.gz", testRuntimeArchive(t, "jre")}, {"paper.jar", []byte("synthetic Paper")}, {"provenance-probe.jar", []byte("synthetic probe")}, {"prepared-runtime.tar.gz", testPreparedRuntimeArchive(t)}, {"target.jar", []byte("synthetic target")}, {"provenance-test-plan.json", probe}}
	c := measuredGuestConfiguration{Version: 1, JobID: "11111111-1111-4111-8111-111111111111", Layout: MeasuredRuntimeLayout{JavaArchiveRoot: "jre", JavaMaximumExpandedBytes: 1024, PreparedMaximumExpandedBytes: 1024}, MemoryBytes: 1 << 30, DiskBytes: 8 << 20, MaximumOutputBytes: 1 << 20}
	for _, value := range values {
		if err := os.WriteFile(filepath.Join(inputRoot, value.name), value.data, 0444); err != nil {
			t.Fatal(err)
		}
		c.Inputs = append(c.Inputs, MeasuredInputIdentity{Name: value.name, SizeBytes: uint64(len(value.data)), SHA256: sha256.Sum256(value.data)})
	}
	return c, inputRoot, workRoot
}

func TestMeasuredGuestPreparationUsesOnlyDerivedFilesAndCommand(t *testing.T) {
	c, inputs, root := guestPreparationFixture(t)
	raw, _ := json.Marshal(c)
	owned, err := prepareMeasuredGuest(context.Background(), raw, inputs, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.workspace.Cleanup(context.Background()) })
	if !strings.HasPrefix(owned.command, owned.workspace.Root()+string(filepath.Separator)) || !strings.HasSuffix(owned.command, "runtime/jre/bin/java") || owned.cwd != filepath.Join(owned.workspace.Root(), "server") {
		t.Fatal("command escaped derived guest tree")
	}
	for _, name := range []string{"paper.jar", "plugins/target.jar", "plugins/provenance-probe.jar", "provenance-test-plan.json", "eula.txt", "server.properties", "cache/patched-runtime.jar"} {
		if _, err := os.Stat(filepath.Join(owned.cwd, name)); err != nil {
			t.Fatal("missing materialized role", name)
		}
	}
	if len(owned.environment) != 4 || strings.Contains(strings.Join(owned.environment, "\n"), "download.example") {
		t.Fatal("unexpected ambient environment")
	}
	if err := owned.workspace.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned.workspace.Root()); !os.IsNotExist(err) {
		t.Fatal("guest workspace retained")
	}
}

func TestMeasuredGuestPreparationRejectsMalformedOrChangedInputs(t *testing.T) {
	for _, mode := range []string{"hash", "writable", "roles", "expanded", "disk", "java-root", "canonical", "archive"} {
		t.Run(mode, func(t *testing.T) {
			c, inputs, root := guestPreparationFixture(t)
			switch mode {
			case "hash":
				c.Inputs[4].SHA256[0] ^= 1
			case "writable":
				if err := os.Chmod(filepath.Join(inputs, "target.jar"), 0600); err != nil {
					t.Fatal(err)
				}
			case "roles":
				c.Inputs[4].Name = "other.jar"
			case "expanded":
				c.Layout.JavaMaximumExpandedBytes = 1
			case "disk":
				c.DiskBytes = 1
			case "java-root":
				c.Layout.JavaArchiveRoot = "../escape"
			case "archive":
				c.Layout.JavaArchiveRoot = "missing"
			}
			raw, _ := json.Marshal(c)
			if mode == "canonical" {
				raw = append(raw, ' ')
			}
			if owned, err := prepareMeasuredGuest(context.Background(), raw, inputs, root); owned != nil || err == nil {
				t.Fatal("invalid preparation accepted")
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "provenance-job-") {
					t.Fatal("failed preparation retained workspace")
				}
			}
		})
	}
}

func TestMeasuredGuestConfigurationRequiresExactPlanAndWorkspaceCapacity(t *testing.T) {
	source, manifest, job := measuredPlanFixture(t)
	plan, err := source.DeriveMeasuredInputPlan(job, manifest, 64<<30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plan.GuestConfiguration(job); err != nil {
		t.Fatal(err)
	}
	job.Artifact.SizeBytes++
	if _, err := plan.GuestConfiguration(job); err == nil {
		t.Fatal("job changed after plan")
	}
	c, _, _ := guestPreparationFixture(t)
	c.Layout.JavaMaximumExpandedBytes = 1 << 30
	if validMeasuredGuestConfiguration(c) {
		t.Fatal("expanded seed exceeds workspace quota")
	}
}
