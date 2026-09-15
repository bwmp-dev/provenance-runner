//go:build linux

package gvisor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/guestoutput"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
)

func measuredPaperGuestFixture(t *testing.T, ctx context.Context, mode string, c measuredSessionConfig, input, out, output *os.File) {
	t.Helper()
	if os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" || os.Getuid() != 0 {
		t.Fatal("explicit disposable Paper fixture required")
	}
	if c.Launch.Measurement.ValidatePaperGuestTarget() != nil {
		t.Fatal("unmeasured Paper helper")
	}
	seed, _ := measuredControllerSessionFixture(t, ctx, c)
	if seed.Close(ctx) != nil {
		t.Fatal("seed controller retirement")
	}
	config := seed.config
	config.MaximumInputBytes = 64 << 20
	controller, err := newMeasuredController(ctx, config)
	if controller != nil {
		t.Cleanup(func() {
			if controller.Close(context.Background()) != nil {
				t.Error("Paper controller cleanup")
			}
		})
	}
	if err != nil {
		t.Fatal("Paper controller construction", err)
	}
	java, err := os.ReadFile("/state-input/guest")
	if err != nil || len(java) > 16<<20 {
		t.Fatal("synthetic Java fixture")
	}
	archive := func(name string, data []byte) []byte {
		var buffer bytes.Buffer
		gz := gzip.NewWriter(&buffer)
		tw := tar.NewWriter(gz)
		if tw.WriteHeader(&tar.Header{Name: name, Mode: 0555, Size: int64(len(data))}) != nil {
			t.Fatal("fixture archive header")
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
		if tw.Close() != nil || gz.Close() != nil {
			t.Fatal("fixture archive close")
		}
		return buffer.Bytes()
	}
	values := []struct {
		name string
		data []byte
	}{{"java.tar.gz", archive("jre/bin/java", java)}, {"paper.jar", []byte("synthetic paper")}, {"provenance-probe.jar", []byte("synthetic probe")}, {"prepared-runtime.tar.gz", archive("cache/patched.jar", []byte("synthetic prepared"))}, {"target.jar", []byte("synthetic target")}, {"provenance-test-plan.json", []byte(`{"targetPlugin":"Fixture","stabilizationMilliseconds":1000}`)}}
	var inputs []measuredInput
	var identities []paper.MeasuredInputIdentity
	for _, value := range values {
		file, err := os.CreateTemp("/tmp", "measured-paper-input-")
		if err != nil {
			t.Fatal(err)
		}
		path := file.Name()
		t.Cleanup(func() { _ = os.Remove(path) })
		if _, err := file.Write(value.data); err != nil {
			t.Fatal(err)
		}
		if file.Chmod(0444) != nil || file.Close() != nil {
			t.Fatal("fixture input sealing")
		}
		file, err = os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		sum := sha256.Sum256(value.data)
		inputs = append(inputs, measuredInput{Name: value.name, Source: file, Size: uint64(len(value.data)), SHA256: sum})
		identities = append(identities, paper.MeasuredInputIdentity{Name: value.name, SizeBytes: uint64(len(value.data)), SHA256: sum})
	}
	// Closed configuration mirror only; signed manifest derivation has its own
	// Paper tests. This fixture makes no real Java/plugin compatibility claim.
	guest := struct {
		Version            int                           `json:"version"`
		JobID              string                        `json:"jobId"`
		Inputs             []paper.MeasuredInputIdentity `json:"inputs"`
		Layout             paper.MeasuredRuntimeLayout   `json:"layout"`
		MemoryBytes        uint64                        `json:"memoryBytes"`
		DiskBytes          uint64                        `json:"diskBytes"`
		MaximumOutputBytes int64                         `json:"maximumOutputBytes"`
	}{1, c.Launch.Job.Lease.JobId, identities, paper.MeasuredRuntimeLayout{JavaArchiveRoot: "jre", JavaMaximumExpandedBytes: uint64(len(java)) + 1024, PreparedMaximumExpandedBytes: 1024}, c.Launch.Job.EffectivePolicy.Resources.MemoryBytes, c.Launch.Job.EffectivePolicy.Resources.DiskBytes, 1 << 20}
	if mode == "session-paper-guest-refusal" {
		guest.Layout.JavaArchiveRoot = "missing"
	}
	raw, err := json.Marshal(guest)
	if err != nil || len(raw) > 4096 {
		t.Fatal("fixture bootstrap bounds")
	}
	if _, err = input.Write(raw); err != nil {
		t.Fatal(err)
	}
	input.Close()
	owned, err := controller.start(ctx, c.Launch.Job, measuredGuestCommand{Command: "/provenance-measured-paper"}, inputs, c.Launch.Authority, c.Launch.Stdin, c.Launch.Stdout, c.Launch.Stderr)
	if owned != nil {
		t.Cleanup(func() {
			if owned.Close(context.Background()) != nil {
				t.Error("Paper job cleanup")
			}
		})
	}
	if err != nil || owned == nil {
		t.Fatal("Paper measured startup", err)
	}
	c.Launch.Stdin.Close()
	out.Close()
	assertRouterThreadsUnprivileged(t, owned.session.router)
	if owned.Release(ctx) != nil {
		t.Fatal("Paper gate release")
	}
	deadline, _ := ctx.Deadline()
	if output.SetReadDeadline(deadline) != nil {
		t.Fatal("fixture output deadline")
	}
	var stdout, stderr bytes.Buffer
	transcript, err := guestoutput.ReadStream(ctx, output, 1<<20, func(kind guestoutput.Kind, data []byte) error {
		if kind == guestoutput.Stdout {
			_, err := stdout.Write(data)
			return err
		}
		_, err := stderr.Write(data)
		return err
	})
	if err != nil {
		t.Fatal("Paper frame stream", err)
	}
	claimedExit, claimedInfrastructure := transcript.ClaimedExit()
	waitErr := owned.Wait(ctx)
	if ctx.Err() != nil {
		t.Fatal("Paper completion missing")
	}
	if mode == "session-paper-guest-refusal" {
		if waitErr == nil || claimedExit != 125 || !claimedInfrastructure || stdout.Len() != 0 || len(transcript.EventBytes()) != 0 {
			t.Fatal("Paper preparation failure not closed", waitErr)
		}
	} else {
		if waitErr != nil || claimedExit != 0 || claimedInfrastructure || !strings.Contains(stdout.String(), "synthetic Paper guest prepared") || !strings.Contains(stderr.String(), "synthetic Paper guest stderr") || string(transcript.EventBytes()) != "{\"syntheticPaperEvent\":true}\n" {
			t.Fatal("Paper preparation or framed result failed", waitErr)
		}
	}
	if !owned.bundle.retired || owned.Release(ctx) == nil || controller.Close(ctx) != nil || c.Uplinks.Recover(ctx) != nil {
		t.Fatal("Paper owned retirement")
	}
}
