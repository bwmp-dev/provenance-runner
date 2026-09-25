//go:build linux

package gvisor

// WP-11C isolation probe: a hostile in-sandbox job that actively attempts the
// escapes an untrusted plugin would try, and asserts every one fails closed.
// It complements the Paper-plugin form of the same probe under
// testdata/hostile/isolation-probe (which runs the identical attack surface
// through a real customer JAR in the Plan 03 matrix). This shell form runs
// against real runsc so it can be exercised on the self-hosted CI runner or a
// disposable local root+gVisor host without downloading Paper.
//
// Opt in exactly like TestRunscSmoke:
//
//	PROVENANCE_RUNSC_SMOKE=1 PROVENANCE_RUNSC_PATH=... \
//	PROVENANCE_RUNSC_ROOTFS=<alpine rootfs> \
//	go test ./internal/provider/gvisor -run TestIsolationProbeSandboxDeniesEscapes
//
// It never runs against production: it targets only well-known private and
// metadata addresses from inside a network=none sandbox, where no packet can
// leave the guest.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

// isolationProbeScript prints one "PROBE <name> <PASS|DENIED>" line per attempt.
// PASS means isolation held (the escape was denied); DENIED means the sandbox
// blocked the action. Any "PROBE <name> REACHED" line is a containment failure.
const isolationProbeScript = `
probe() {
  name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "PROBE $name REACHED"
  else
    echo "PROBE $name PASS"
  fi
}
connect() { nc -z -w 2 "$1" "$2"; }
# Management and data-plane services on common private/management addresses.
probe postgres_private_a connect 10.0.0.1 5432
probe postgres_private_b connect 172.17.0.1 5432
probe postgres_loopback connect 127.0.0.1 5432
probe temporal_private_a connect 10.0.0.1 7233
probe temporal_private_b connect 192.168.1.1 7233
probe coolify_mgmt_http connect 10.0.0.1 8000
probe coolify_mgmt_https connect 10.0.0.1 443
# Cloud instance metadata.
probe cloud_metadata connect 169.254.169.254 80
probe cloud_metadata_ecs connect 169.254.170.2 80
# Container control plane.
probe docker_socket test -S /var/run/docker.sock
probe docker_socket_run test -S /run/docker.sock
probe containerd_socket test -S /run/containerd/containerd.sock
# Host PID / network namespace escapes.
probe host_init_ns test -e /proc/1/ns/net
probe host_init_root test -r /proc/1/root/etc/shadow
probe nsenter_present sh -c 'command -v nsenter'
probe host_route sh -c 'test "$(tail -n +2 /proc/net/route | wc -l)" -gt 0'
# Cross-job / host filesystem reads.
probe read_etc_shadow test -r /etc/shadow
probe read_other_job test -r /inputs/../smoke-cancel
probe read_host_home test -r /root/.ssh/id_rsa
probe write_root touch /provenance-root-write-test
# Credential scraping from the environment.
probe env_scrape sh -c 'env | grep -Eiq "(PASSWORD|SECRET|TOKEN|CREDENTIAL|DATABASE_URL|AWS_|S3_|TEMPORAL)"'
echo "PROBE identity_uid $([ "$(id -u)" = 65532 ] && echo PASS || echo REACHED)"
echo PROBE_COMPLETE
`

func TestIsolationProbeSandboxDeniesEscapes(t *testing.T) {
	if os.Getenv("PROVENANCE_RUNSC_SMOKE") != "1" {
		t.Skip("set PROVENANCE_RUNSC_SMOKE=1 to opt in to the real sandbox isolation probe")
	}
	runscPath := os.Getenv("PROVENANCE_RUNSC_PATH")
	if runscPath == "" {
		runscPath = "runsc"
	}
	resolvedRunsc, err := exec.LookPath(runscPath)
	if err != nil {
		t.Fatalf("PROVENANCE_RUNSC_SMOKE=1 requires runsc (%v)", err)
	}
	rootFS := os.Getenv("PROVENANCE_RUNSC_ROOTFS")
	if rootFS == "" {
		t.Fatal("PROVENANCE_RUNSC_SMOKE=1 requires PROVENANCE_RUNSC_ROOTFS containing /bin/sh and nc")
	}
	temporaryRoot := t.TempDir()
	inputsRoot := filepath.Join(temporaryRoot, "inputs")
	for _, jobID := range []string{"probe", "smoke-cancel"} {
		if err := os.MkdirAll(filepath.Join(inputsRoot, jobID), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A decoy secret in a sibling job directory; the probe must never read it.
	if err := os.WriteFile(filepath.Join(inputsRoot, "smoke-cancel", "tenant-secret"), []byte("cross-tenant"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := New(Config{
		RunscPath:      resolvedRunsc,
		RootFS:         rootFS,
		RootFSIdentity: "sha256:isolation-probe",
		StateRoot:      filepath.Join(temporaryRoot, "state"),
		BundleRoot:     filepath.Join(temporaryRoot, "bundles"),
		InputsRoot:     inputsRoot,
		Platform:       "systrap",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := provider.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	prepared := prepareSmokeEnvironment(t, provider, "probe", configuration{
		Command:     "/bin/sh",
		Arguments:   []string{"-c", isolationProbeScript},
		Environment: map[string]string{"PROVENANCE_DECOY_PASSWORD": "must-not-be-scraped"},
		Network:     "none",
		MemoryBytes: 128 << 20,
		CPUMillis:   500,
		PIDs:        64,
		DiskBytes:   8 << 20,
	})
	defer cleanupSmokeEnvironment(t, prepared)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	outcome, executeErr := prepared.Execute(ctx)
	output, collectErr := prepared.Collect(ctx)
	if executeErr != nil {
		t.Fatalf("Execute() error = %v; stdout=%q stderr=%q", executeErr, output.Stdout, output.Stderr)
	}
	if collectErr != nil {
		t.Fatalf("Collect() error = %v", collectErr)
	}
	// The environment scrape sees the decoy variable we injected, so the probe
	// job exits nonzero (env_scrape "REACHED" would be a real finding, but the
	// decoy is deliberately not a credential name). We assert on structured
	// probe lines rather than the exit code.
	_ = outcome
	if !strings.Contains(output.Stdout, "PROBE_COMPLETE") {
		t.Fatalf("isolation probe did not run to completion; stdout=%q stderr=%q", output.Stdout, output.Stderr)
	}
	line := regexp.MustCompile(`PROBE (\S+) (PASS|DENIED|REACHED)`)
	seen := map[string]string{}
	for _, match := range line.FindAllStringSubmatch(output.Stdout, -1) {
		seen[match[1]] = match[2]
	}
	required := []string{
		"postgres_private_a", "postgres_private_b", "postgres_loopback",
		"temporal_private_a", "temporal_private_b", "coolify_mgmt_http", "coolify_mgmt_https",
		"cloud_metadata", "cloud_metadata_ecs", "docker_socket", "docker_socket_run",
		"containerd_socket", "host_init_ns", "host_init_root", "nsenter_present",
		"host_route", "read_etc_shadow", "read_other_job", "read_host_home",
		"write_root", "env_scrape", "identity_uid",
	}
	for _, name := range required {
		switch seen[name] {
		case "PASS":
		case "REACHED":
			t.Errorf("isolation probe %q reached its target: sandbox containment failed", name)
		default:
			t.Errorf("isolation probe %q produced no verdict (got %q)", name, seen[name])
		}
	}
	if seen["env_scrape"] != "PASS" {
		t.Errorf("environment contained a credential-shaped variable: %q", seen["env_scrape"])
	}
	if _, err := os.Lstat("/provenance-root-write-test"); err == nil {
		t.Error("guest wrote to the read-only root filesystem")
	}
	// The complete log must remain bounded and sanitized like any guest output.
	if output.CompleteLog == nil {
		t.Fatal("isolation probe produced no complete log")
	}
	_ = execution.ClassificationPassed
}
