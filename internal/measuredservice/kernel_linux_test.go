//go:build linux

package measuredservice

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/provider/gvisor"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fixtureResolver struct{}

func (fixtureResolver) Exchange(_ context.Context, raw []byte) ([]byte, error) {
	var query dnsmessage.Message
	if err := query.Unpack(raw); err != nil || len(query.Questions) != 1 {
		return nil, np.ErrDNS
	}
	q := query.Questions[0]
	answer := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 20}}
	switch q.Type {
	case dnsmessage.TypeA:
		answer.Body = &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}
	case dnsmessage.TypeAAAA:
		answer.Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1111").As16()}
	default:
		return nil, np.ErrDNS
	}
	return (&dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions, Answers: []dnsmessage.Resource{answer}}).Pack()
}

func fixtureArchive(t *testing.T, name string, raw []byte, mode int64) []byte {
	t.Helper()
	var data bytes.Buffer
	zip := gzip.NewWriter(&data)
	archive := tar.NewWriter(zip)
	if archive.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(raw)), Typeflag: tar.TypeReg}) != nil {
		t.Fatal("archive header")
	}
	if _, err := archive.Write(raw); err != nil {
		t.Fatal(err)
	}
	if archive.Close() != nil || zip.Close() != nil {
		t.Fatal("archive close")
	}
	return data.Bytes()
}

func TestMeasuredPaperServiceKernel(t *testing.T) {
	measuredPaperServiceKernel(t, "complete")
}

func TestMeasuredPaperServiceWithdrawalKernel(t *testing.T) {
	measuredPaperServiceKernel(t, "withdraw")
}

func TestMeasuredPaperServiceReleaseRefusalKernel(t *testing.T) {
	measuredPaperServiceKernel(t, "reject-release")
}

func TestMeasuredPaperServiceEventRefusalKernel(t *testing.T) {
	measuredPaperServiceKernel(t, "reject-events")
}

func TestMeasuredPaperDaemonKernel(t *testing.T) {
	measuredPaperServiceKernel(t, "daemon")
}

func TestMeasuredPaperWorkerKernel(t *testing.T) {
	measuredPaperServiceKernel(t, "worker")
}

func measuredPaperServiceKernel(t *testing.T, mode string) {
	if os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" {
		t.Skip("explicit disposable service fixture required")
	}
	if os.Getuid() != 0 || os.Getgid() != 0 {
		t.Fatal("disposable root service required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container required")
	}
	if syscall.Setgroups([]int{}) != nil {
		t.Fatal("empty supplementary groups")
	}
	t.Run("root-idle-response-refusal", idleRefusalFixture)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("/tmp", "measured-service-")
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(root, 0711) != nil {
		t.Fatal("service root")
	}
	var fixtureFiles []string
	t.Cleanup(func() {
		// Every owner and input descriptor closes before this last cleanup.
		// Preserve failed-case diagnostics; successful repetitions must not
		// accumulate executable/input copies in the bounded fixture tmpfs.
		if t.Failed() {
			return
		}
		for _, path := range fixtureFiles {
			if err := os.Remove(path); err != nil {
				t.Error("fixture input retirement", err)
			}
		}
		if err := os.Remove(root); err != nil {
			t.Error("fixture directory retirement", err)
		}
	})
	state, err := os.MkdirTemp("/state-input", "service-journals-")
	if err != nil {
		t.Fatal(err)
	}
	openDir := func(path string, mode os.FileMode) *os.File {
		if os.Mkdir(path, mode) != nil {
			t.Fatal("fixture directory")
		}
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	groupState := openDir(filepath.Join(state, "cgroups"), 0700)
	bundleState := openDir(filepath.Join(state, "bundles"), 0700)
	uplinkState := openDir(filepath.Join(state, "uplinks"), 0700)
	// The driver bind-mounts fresh persistent storage here. /tmp itself is
	// tmpfs and must not satisfy the durable bundle ownership requirement.
	bundlePath, err := os.MkdirTemp("/tmp/bundle-input", "service-")
	if err != nil || os.Chmod(bundlePath, 0711) != nil {
		t.Fatal("persistent fixture bundle directory")
	}
	bundleRoot, err := os.Open(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bundleRoot.Close()
		// Remove only the now-empty directory we created; preserve failures.
		if os.Remove(bundlePath) != nil {
			t.Error("fixture bundle directory retained")
		}
	})
	parent, err := os.Open("/sys/fs/cgroup/provenance-fixture-jobs")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := io.ReadAll(io.LimitReader(self, (64<<20)+1))
	self.Close()
	if err != nil || len(executable) > 64<<20 {
		t.Fatal("bounded test executable")
	}
	java := fixtureArchive(t, "jre/bin/java", executable, 0755)
	prepared := fixtureArchive(t, "cache/patched.jar", []byte("synthetic prepared"), 0600)
	probe, err := os.ReadFile("/opt/provenance-fixture/paper-probe.jar")
	digest := sha256.Sum256(probe)
	if err != nil || int64(len(probe)) != paper.AlphaProbeSizeBytes || hex.EncodeToString(digest[:]) != paper.AlphaProbeSHA256 {
		t.Fatal("accepted probe fixture identity")
	}
	source, manifest, job := serviceFixtureJob(t, java, prepared)
	limits := job.EffectivePolicy.Resources
	controls := [][2]string{{"cpu.max", strconv.FormatUint(2*uint64(limits.CpuMillis)*100, 10) + " 100000"}, {"cpu.max.burst", "0"}, {"memory.max", strconv.FormatUint(2*limits.MemoryBytes, 10)}, {"memory.swap.max", "0"}, {"pids.max", strconv.FormatUint(2*(uint64(limits.ProcessCount)+np.MappedRuntimeProcessReserve), 10)}, {"cgroup.max.descendants", "2"}, {"cgroup.max.depth", "1"}, {"memory.oom.group", "1"}}
	for _, control := range controls {
		path := "/sys/fs/cgroup/provenance-fixture-jobs/" + control[0]
		previous, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if os.WriteFile(path, previous, 0600) != nil {
				t.Error("restore fixture control")
			}
		})
		if os.WriteFile(path, []byte(control[1]), 0600) != nil {
			t.Fatal("fixture resource provisioning")
		}
	}
	groups, err := np.OpenJobCgroupJournal(parent, groupState)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if groups.Close() != nil {
			t.Error("service cgroup journal retained")
		}
	})
	bundles, err := gvisor.OpenMeasuredBundleJournal(bundleRoot, bundleState, groups)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if bundles.Close() != nil {
			t.Error("service bundle journal retained")
		}
	})
	tool := func(name string) np.ProtectedRouteTool {
		path, e := exec.LookPath(name)
		if e != nil {
			t.Fatal(e)
		}
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { f.Close() })
		raw, e := io.ReadAll(io.LimitReader(f, (32<<20)+1))
		if e != nil || len(raw) > 32<<20 {
			t.Fatal("tool identity")
		}
		return np.ProtectedRouteTool{File: f, SHA256: sha256.Sum256(raw)}
	}
	tools := np.RouteTools{NSenter: tool("nsenter"), NFT: tool("nft"), IP: tool("ip")}
	uplinks, err := np.OpenHostUplinkJournal(uplinkState, tools)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if uplinks.Close() != nil {
			t.Error("service uplink journal retained")
		}
	})
	lease, err := runtimeidentity.Acquire(ctx, "/tmp/provenance-runtime-fixture/runsc", "/tmp/provenance-runtime-fixture/mount", "/tmp/provenance-runtime-fixture/image.squashfs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Close() })
	boundary, err := gvisor.NewMeasuredLocalBoundary(job.EffectivePolicy, np.MappedIdentity{UID: 40000, GID: 40000, OverflowUID: 40001, OverflowGID: 40001}, np.MappedIdentity{UID: 40002, GID: 40002, OverflowUID: 40003, OverflowGID: 40003}, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := gvisor.OpenMeasuredController(ctx, gvisor.MeasuredControllerConfig{Bundles: bundles, Uplinks: uplinks, Measurement: lease, Boundary: boundary, Tools: tools, Resolver: fixtureResolver{}, BundleRoot: bundlePath, MaximumInputBytes: 64 << 20})
	if controller != nil {
		t.Cleanup(func() {
			if controller.Close(context.Background()) != nil {
				t.Error("service controller retained")
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(ctx, Config{Controller: controller, Measurement: lease, RuntimeSource: source, WorkerUID: 65532, MaximumInputBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if server.Close(context.Background()) != nil {
			t.Error("service cleanup")
		}
	})
	request, err := paper.EncodeMeasuredRequest(job, manifest)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := source.DeriveMeasuredInputPlan(job, manifest, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string][]byte{"java.tar.gz": java, "paper.jar": []byte("synthetic paper"), "provenance-probe.jar": probe, "prepared-runtime.tar.gz": prepared, "target.jar": []byte("synthetic target"), "provenance-test-plan.json": plan.ProbePlan()}
	write := func(name string, raw []byte) *os.File {
		path := filepath.Join(root, name)
		fixtureFiles = append(fixtureFiles, path)
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("fixture input")
		}
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	now := time.Now()
	ack, err := np.EncodeAuthorityUpdate(np.AuthorityUpdate{Reconciliation: &p.LeaseReconciliation{Lease: job.Lease, Attempt: job.Attempt, Status: p.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: p.JobPhase_JOB_PHASE_RUNNING, Disposition: p.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE, NetworkAuthorityV2: &p.NetworkAuthorityV2{Policy: job.Hashes.Policy, State: p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT, CheckedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(40 * time.Second))}}, Features: []p.ProtocolFeature{1, 3, 9, 10}, CredentialExpiry: job.Lease.ExpiresAt.AsTime()})
	if err != nil {
		t.Fatal(err)
	}
	files := []*os.File{write("request", request), write("ack", ack)}
	for i, role := range plan.Inputs() {
		files = append(files, write(fmt.Sprintf("input-%d", i), contents[role.Name]))
	}
	clientPath := filepath.Join(root, "client")
	fixtureFiles = append(fixtureFiles, clientPath)
	if os.WriteFile(clientPath, executable, 0555) != nil {
		t.Fatal("fixture client")
	}
	listenerRoot, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer listenerRoot.Close()
	listener, err := cc.OpenRootListener(listenerRoot, 65532, 65532)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var daemon *Daemon
	var daemonDone chan error
	clientMode := mode
	if mode == "daemon" || mode == "worker" {
		clientMode = "complete"
		// Retire the manual fixture provisioner before testing the complete
		// daemon's reopening/recovery of these same owned, empty journals.
		if listener.Close() != nil || server.Close(ctx) != nil || uplinks.Close() != nil || bundles.Close() != nil || groups.Close() != nil {
			t.Fatal("retire fixture provisioner before daemon")
		}
		daemon = openFixtureDaemon(t, ctx, root, state, bundlePath, lease, tools, source, job)
		listener, server = daemon.listener, daemon.server
		daemonDone = make(chan error, 1)
		go func() { daemonDone <- daemon.Serve() }()
		t.Cleanup(func() {
			if daemon.Close(context.Background()) != nil {
				t.Error("daemon ownership retained")
			}
			if daemonDone != nil {
				<-daemonDone
			}
		})
	}
	command := exec.CommandContext(ctx, clientPath, "service-client", filepath.Join(root, cc.SocketName), clientMode)
	command.Env = []string{"PATH=/usr/bin:/bin", "PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE=1"}
	if mode == "worker" {
		command = exec.CommandContext(ctx, "/tmp/measured-worker.test", "-test.run=^TestMeasuredWorkerRootFixture$", "-test.timeout=40s")
		command.Env = []string{"PATH=/usr/bin:/bin", "PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE=1", "PROVENANCE_DISPOSABLE_WORKER_ROOT_SOCKET=" + filepath.Join(root, cc.SocketName)}
	}
	command.ExtraFiles = files
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL}
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	clientDone := make(chan error, 1)
	go func() { runtime.LockOSThread(); defer runtime.UnlockOSThread(); clientDone <- command.Run() }()
	var serveErr error
	if daemon == nil {
		channel, err := listener.Accept(time.Now().Add(5 * time.Second))
		if err != nil {
			cancel()
			<-clientDone
			t.Fatal("service client acceptance", err, diagnostic.String())
		}
		serveErr = server.Serve(ctx, channel)
	}
	clientErr := <-clientDone
	if (serveErr != nil) != (clientMode != "complete" && clientMode != "reject-events") || clientErr != nil {
		t.Fatal("signed service execution", serveErr, clientErr, diagnostic.String())
	}
	t.Run("root-idle-barrier-after-retirement", func(t *testing.T) {
		probe := exec.CommandContext(ctx, clientPath, "service-idle", filepath.Join(root, cc.SocketName))
		probe.Env = command.Env
		probe.SysProcAttr = command.SysProcAttr
		var output bytes.Buffer
		probe.Stderr = &output
		done := make(chan error, 1)
		go func() { runtime.LockOSThread(); defer runtime.UnlockOSThread(); done <- probe.Run() }()
		var serveErr error
		if daemon == nil {
			channel, err := listener.Accept(time.Now().Add(5 * time.Second))
			if err != nil {
				cancel()
				<-done
				t.Fatal("idle probe admission", err)
			}
			serveErr = server.Serve(ctx, channel)
		}
		if clientErr := <-done; serveErr != nil || clientErr != nil {
			t.Fatal("authenticated idle barrier", serveErr, clientErr, output.String())
		}
	})
	if daemon != nil {
		if daemon.Close(ctx) != nil {
			t.Fatal("daemon retirement")
		}
		<-daemonDone
		daemonDone = nil
	}
	if server.Close(ctx) != nil || listener.Close() != nil {
		t.Fatal("service retirement")
	}
	for _, directory := range []string{filepath.Join(state, "cgroups"), filepath.Join(state, "bundles"), filepath.Join(state, "uplinks")} {
		entries, e := os.ReadDir(directory)
		if e != nil || len(entries) != 1 || entries[0].Name() != ".lock" {
			t.Fatal("service journal records retained")
		}
	}
	entries, err := os.ReadDir(bundlePath)
	if err != nil || len(entries) != 0 {
		t.Fatal("service bundle retained")
	}
}
