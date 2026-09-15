//go:build linux

package gvisor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestMeasuredRouteFixtureHelper(t *testing.T) {
	mode := os.Getenv("PROVENANCE_RETAINED_HELPER")
	if mode == "" {
		t.Skip("disposable retained helper only")
	}
	if os.Getuid() != 0 || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		os.Exit(2)
	}
	// Mapped holders cannot inspect the outer root process's namespace. Their
	// trusted parent verifies the retained child and namespace ownership.
	if mode == "holder" {
		fmt.Fprintln(os.Stdout, "ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		os.Exit(2)
	}
	parent, err := os.Stat("/proc/1/ns/net")
	if err != nil {
		os.Exit(2)
	}
	if mode == "host-uplink-server" {
		if !os.SameFile(current, parent) {
			os.Exit(2)
		}
		if _, err := os.Stat("/.dockerenv"); err != nil {
			os.Exit(2)
		}
		interfaces, err := net.Interfaces()
		if err != nil || len(interfaces) != 2 {
			os.Exit(2)
		}
		for _, link := range interfaces {
			if link.Name != "lo" && (!strings.HasPrefix(link.Name, "ph") || len(link.Name) != 15) {
				os.Exit(2)
			}
		}
	} else if mode != "server" || os.SameFile(current, parent) {
		os.Exit(2)
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, port := range []string{"8080", "8081", "8082"} {
			address := "0.0.0.0:" + port
			if network == "tcp6" {
				address = "[::]:" + port
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				os.Exit(2)
			}
			go func() {
				for {
					connection, err := listener.Accept()
					if err != nil {
						return
					}
					go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
				}
			}()
		}
	}
	for _, network := range []string{"udp4", "udp6"} {
		addresses := []string{"1.1.1.1", "1.0.0.1", "169.254.169.254", "10.0.2.2"}
		if network == "udp6" {
			addresses = []string{"2606:4700:4700::1111", "2606:4700:4700::1001", "fd00:2::2"}
		}
		for _, host := range addresses {
			for _, port := range []string{"8080", "8081", "8082"} {
				address := net.JoinHostPort(host, port)
				socket, err := net.ListenPacket(network, address)
				if err != nil {
					os.Exit(2)
				}
				go func() {
					var buffer [4096]byte
					for {
						n, peer, err := socket.ReadFrom(buffer[:])
						if err != nil {
							return
						}
						if _, err := socket.WriteTo(buffer[:n], peer); err != nil {
							return
						}
					}
				}()
			}
		}
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]bool{"serverReady": true}) != nil {
		os.Exit(2)
	}
	select {}
}

func TestMeasuredAuthorityRouteSentryWithdrawal(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "withdrawal")
}

func TestMeasuredAuthorityRouteSentryExpiry(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "expiry")
}

func TestMeasuredAuthorityRouteSentryChildMismatch(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "child-mismatch")
}

func TestMeasuredAuthorityRouteSentryOwnedLaunch(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "owned-launch")
}

func TestMeasuredAuthorityRouteSentryOwnedNormal(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "owned-normal")
}

func TestMeasuredAuthorityRouteSentryOwnedGatedStartup(t *testing.T) {
	for i := 0; i < 10; i++ {
		if !t.Run(strconv.Itoa(i), func(t *testing.T) {
			testMeasuredAuthorityRouteSentry(t, "owned-gated-startup")
		}) {
			return
		}
	}
}

func TestMeasuredAuthorityRouteSentryJournalRefusal(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "journal-refusal")
}

func TestMeasuredAuthorityRouteSentryBundleRefusal(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "bundle-refusal")
}

func TestMeasuredAuthorityRouteSentryPreparedRefusal(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "prepared-refusal")
}

func TestMeasuredAuthorityRouteSentryLinkRefusal(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "link-refusal")
}

func TestMeasuredAuthorityRouteSentryLayoutRefusal(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "layout-refusal")
}

func TestMeasuredAuthorityRouteSentryUplinkRefusal(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "uplink-refusal")
}

func TestMeasuredNetworkSessionNormal(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "session-normal")
}
func TestMeasuredNetworkSessionRouterLoss(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "session-router-loss")
}
func TestMeasuredNetworkSessionStartupRefusal(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "session-startup-refusal")
}
func TestMeasuredNetworkSessionDNSLoss(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "session-dns-loss")
}
func TestMeasuredNetworkSessionDNSRefreshFailure(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "session-dns-refresh-failure")
}
func TestMeasuredNetworkSessionPreparationTimeout(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "session-preparation-timeout")
}
func TestMeasuredNetworkSessionExecutionTimeout(t *testing.T) {
	testMeasuredAuthorityRouteSentry(t, "session-execution-timeout")
}

func testMeasuredAuthorityRouteSentry(t *testing.T, authorityMode string) {
	t.Helper()
	if authorityMode != "session-preparation-timeout" && authorityMode != "session-execution-timeout" && authorityMode != "session-dns-refresh-failure" && authorityMode != "session-dns-loss" && authorityMode != "session-normal" && authorityMode != "session-router-loss" && authorityMode != "session-startup-refusal" && authorityMode != "withdrawal" && authorityMode != "expiry" && authorityMode != "child-mismatch" && authorityMode != "owned-launch" && authorityMode != "owned-normal" && authorityMode != "owned-gated-startup" && authorityMode != "journal-refusal" && authorityMode != "bundle-refusal" && authorityMode != "prepared-refusal" && authorityMode != "link-refusal" && authorityMode != "layout-refusal" && authorityMode != "uplink-refusal" && authorityMode != "uplink-crash" {
		t.Fatal("unknown measured authority case")
	}
	if os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" {
		t.Skip("explicit disposable Sentry fixture required")
	}
	if os.Getuid() != 0 || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		t.Fatal("disposable root controller required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container required")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("fixture must have network=none")
	}
	if syscall.Setgroups([]int{}) != nil {
		t.Fatal("disposable group drop unavailable")
	}
	// Only this fresh container's private mount namespace gets a writable proc
	// view. The router child configures forwarding solely in its own fresh net.
	if unix.Mount("proc", "/proc", "proc", 0, "") != nil {
		t.Fatal("disposable proc view unavailable")
	}
	t.Cleanup(func() {
		if unix.Unmount("/proc", 0) != nil {
			t.Error("disposable proc cleanup failed")
		}
	})
	parentForwarding := map[string]string{}
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding", "/proc/sys/net/ipv6/conf/default/forwarding", "/proc/sys/net/ipv4/conf/all/send_redirects", "/proc/sys/net/ipv4/conf/default/send_redirects", "/proc/sys/net/ipv6/conf/all/accept_ra", "/proc/sys/net/ipv6/conf/default/accept_ra"} {
		value, err := os.ReadFile(path)
		if err != nil || len(value) > 3 {
			t.Fatal("parent forwarding observation")
		}
		parentForwarding[path] = string(value)
	}
	checkParentForwarding := func() {
		t.Helper()
		for path, expected := range parentForwarding {
			value, err := os.ReadFile(path)
			if err != nil || string(value) != expected {
				t.Error("router changed parent networking")
			}
		}
	}
	t.Cleanup(checkParentForwarding)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	const job = "10000000-0000-4000-8000-000000000001"
	const fixtureRoot = "/tmp/provenance-runtime-fixture"
	policy := &runnerv1.EffectivePolicy{Sandbox: runnerv1.SandboxKind_SANDBOX_KIND_GVISOR, Requirement: runnerv1.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED,
		Resources: &runnerv1.ResourceLimits{CpuMillis: 2000, MemoryBytes: 1 << 30, DiskBytes: 2 << 20, ProcessCount: 256}, PreparationTimeout: durationpb.New(time.Minute), ExecutionTimeout: durationpb.New(time.Minute), GracefulShutdownTimeout: durationpb.New(10 * time.Second),
		NetworkV2: &runnerv1.NetworkPolicyV2{Mode: runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST, MaximumConnections: 16, MaximumBytesPerSecond: 65536, Permissions: []*runnerv1.NetworkPermissionV2{{Hostname: "fixture.example.com", Port: 8080, Transport: runnerv1.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP}, {Hostname: "fixture.example.com", Port: 8081, Transport: runnerv1.NetworkTransportV2_NETWORK_TRANSPORT_V2_UDP}}}}
	if authorityMode == "session-preparation-timeout" {
		policy.PreparationTimeout = durationpb.New(10 * time.Millisecond)
	}
	if authorityMode == "session-execution-timeout" {
		policy.ExecutionTimeout = durationpb.New(7 * time.Second)
	}
	policyRaw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(policyRaw)
	credentialExpiry := time.Now().Add(2 * time.Minute)
	specification := &runnerv1.JobSpecification{
		Lease:           &runnerv1.LeaseIdentity{JobId: job, LeaseId: "20000000-0000-4000-8000-000000000001", ExecutionId: "30000000-0000-4000-8000-000000000001", ExpiresAt: timestamppb.New(credentialExpiry)},
		Attempt:         &runnerv1.AttemptIdentity{AttemptId: "40000000-0000-4000-8000-000000000001", ReleaseCandidateId: "50000000-0000-4000-8000-000000000001", MatrixEntryId: "60000000-0000-4000-8000-000000000001", AttemptNumber: 1},
		EffectivePolicy: policy, Hashes: &runnerv1.JobHashes{Policy: &runnerv1.Digest{Algorithm: runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}},
	}
	evidenceContext := measuredEvidenceFixture(t, specification)
	parent, err := os.Open("/sys/fs/cgroup/provenance-fixture-jobs")
	if err != nil {
		t.Fatal(err)
	}
	state, err := os.Open("/state-input/journal")
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	journal, err := np.OpenJobCgroupJournal(parent, state)
	parent.Close()
	state.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error("measured journal closure", err)
		}
	})
	bundleParent, err := os.Open("/tmp/bundle-input")
	if err != nil {
		t.Fatal(err)
	}
	bundleState, err := os.Open("/state-input/bundle-journal")
	if err != nil {
		bundleParent.Close()
		t.Fatal(err)
	}
	bundles, err := openMeasuredBundleJournal(bundleParent, bundleState, journal)
	bundleParent.Close()
	bundleState.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bundles.close(); err != nil {
			t.Error(err)
		}
	})
	if err := bundles.recover(ctx); err != nil {
		t.Fatal("bundle recovery", err)
	}
	ownedBundle, err := bundles.create(specification)
	if ownedBundle != nil {
		t.Cleanup(func() {
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := bundles.cleanup(stop, ownedBundle); err != nil {
				t.Error("journaled bundle cleanup", err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	jobScope := ownedBundle.scope
	cleanupScope := func() bool {
		if jobScope != nil {
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := journal.Cleanup(stop, jobScope); err != nil {
				t.Error("exclusive Sentry scope cleanup", err)
				return false
			}
		}
		return true
	}
	t.Cleanup(func() { cleanupScope() })
	if err != nil {
		t.Fatal(err)
	}
	jobScopeFD, err := jobScope.LaunchFD(specification)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { jobScopeFD.Close() })
	lease, err := runtimeidentity.Acquire(ctx, fixtureRoot+"/runsc", fixtureRoot+"/mount", fixtureRoot+"/image.squashfs")
	if err != nil {
		t.Fatal(err)
	}
	retained, err := lease.Retain()
	if err != nil {
		lease.Close()
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		retained.Close()
		t.Fatal(err)
	}
	lease = retained
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	})
	bundle := "/tmp/bundle-input/" + job
	privateRoot := bundle + "/.measured-root"
	input, sourcePath := measuredFixtureInput(t, ctx)
	mode := "probe-confined-lifecycle"
	if authorityMode == "owned-normal" || authorityMode == "session-normal" {
		mode = "probe-confined"
	}
	if strings.HasPrefix(authorityMode, "session-") {
		mode = "probe-confined-dns-lifecycle"
		if authorityMode == "session-normal" {
			mode = "probe-confined-dns"
		}
	}
	mapping := np.MappedIdentity{UID: 65532, GID: 65532, OverflowUID: 65533, OverflowGID: 65533}
	if ownedBundle.prepare(ctx, specification, measuredGuestCommand{Command: "/smoke", Arguments: []string{mode}}, privateRoot, mapping, []measuredInput{input}, 2<<20) != nil || ownedBundle.checkPrepared(mapping) != nil {
		t.Fatal("closed bundle preparation")
	}
	// Later source mutation cannot change the independently verified copy.
	if os.WriteFile(sourcePath, []byte("changed-source"), 0444) != nil {
		t.Fatal("synthetic source mutation")
	}
	var release *os.File
	cgroup, err := os.OpenFile("/sys/fs/cgroup/provenance-fixture-controller", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cgroup.Close() })
	if uint64(gvisorRuntimePIDReserve) != np.MappedRuntimeProcessReserve {
		t.Fatal("resource profile reserve drift")
	}
	guard, err := np.NewAuthorityRoute(ctx, specification)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := guard.Close(); err != nil {
			t.Error("authority route cleanup", err)
		}
	})
	features := []runnerv1.ProtocolFeature{1, 3, 9, 10}
	now := time.Now()
	receipt := &runnerv1.LeaseReconciliation{Lease: specification.Lease, Attempt: specification.Attempt, Status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE,
		NetworkAuthorityV2: &runnerv1.NetworkAuthorityV2{Policy: specification.Hashes.Policy, State: runnerv1.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT, CheckedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(40 * time.Second))}}
	if err := guard.Reconcile(ctx, receipt, features, credentialExpiry); err != nil {
		t.Fatal(err)
	}
	var launchOwner *MeasuredNetworkProcess
	load := func(path string) np.ProtectedRouteTool {
		t.Helper()
		resolved, err := exec.LookPath(path)
		if err != nil {
			t.Fatal("fixture executable missing")
		}
		f, err := os.Open(resolved)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			t.Fatal(err)
		}
		return np.ProtectedRouteTool{File: f, SHA256: [32]byte(h.Sum(nil))}
	}
	tools := np.RouteTools{NSenter: load("nsenter"), NFT: load("nft"), IP: load("ip")}
	self := load(os.Args[0])
	if strings.HasPrefix(authorityMode, "session-") {
		testMeasuredSessionFixture(t, ctx, authorityMode, measuredSessionConfig{Launch: MeasuredNetworkLaunchConfig{Job: specification, Measurement: lease, Scope: jobScope, Journal: journal, Bundle: ownedBundle, Authority: guard, Mapping: mapping, PrivateRoot: privateRoot}, RouterMapping: np.MappedIdentity{UID: 65530, GID: 65530, OverflowUID: 65531, OverflowGID: 65531}, Tools: tools}, self)
		checkParentForwarding()
		return
	}
	executeContext := func(commandContext context.Context, fd *os.File, tool np.ProtectedRouteTool, args ...string) ([]byte, error) {
		command := exec.CommandContext(commandContext, "/proc/self/fd/4")
		command.Args = append([]string{"nsenter", "-F", "--preserve-credentials", "-n/proc/self/fd/3", "--", "/proc/self/fd/5"}, args...)
		command.ExtraFiles = []*os.File{fd, tools.NSenter.File, tool.File}
		command.Env = []string{"PATH=/usr/bin:/bin"}
		return command.Output()
	}
	execute := func(fd *os.File, tool np.ProtectedRouteTool, args ...string) ([]byte, error) {
		return executeContext(ctx, fd, tool, args...)
	}
	read := func(reader *bufio.Reader) map[string]any {
		t.Helper()
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) > 4096 {
			t.Fatal("bounded native fixture report missing")
		}
		var value map[string]any
		if json.Unmarshal(line, &value) != nil {
			t.Fatal("invalid native fixture report")
		}
		return value
	}
	child := func(uid uint32, sentry bool) (*np.ChildNamespaces, *exec.Cmd, io.WriteCloser, *bufio.Reader, *os.File) {
		t.Helper()
		if sentry && (authorityMode == "owned-launch" || authorityMode == "owned-normal" || authorityMode == "owned-gated-startup" || authorityMode == "journal-refusal" || authorityMode == "bundle-refusal" || authorityMode == "prepared-refusal" || authorityMode == "link-refusal" || authorityMode == "layout-refusal" || authorityMode == "uplink-refusal" || authorityMode == "uplink-crash") {
			inputRead, inputWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { inputRead.Close(); inputWrite.Close() })
			outputRead, outputWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { outputRead.Close(); outputWrite.Close() })
			diagnostics, err := os.CreateTemp("/tmp", "measured-owner-diagnostic-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if t.Failed() {
					if f, err := os.Open(diagnostics.Name()); err == nil {
						raw, _ := io.ReadAll(io.LimitReader(f, 4096))
						f.Close()
						t.Logf("owned launch diagnostic: %s", raw)
					}
				}
				diagnostics.Close()
				os.Remove(diagnostics.Name())
			})
			launchOwner, err = StartMeasuredNetworkProcess(ctx, MeasuredNetworkLaunchConfig{Job: specification, Measurement: lease, Scope: jobScope, Journal: journal, Bundle: ownedBundle, Authority: guard,
				Mapping: np.MappedIdentity{UID: uid, GID: uid, OverflowUID: uid + 1, OverflowGID: uid + 1}, PrivateRoot: privateRoot, Stdin: inputRead, Stdout: outputWrite, Stderr: diagnostics})
			if launchOwner != nil {
				t.Cleanup(func() {
					if err := launchOwner.Close(context.Background()); err != nil {
						t.Error(err)
					}
				})
			}
			if err != nil {
				t.Fatal("owned measured launch", err)
			}
			inputRead.Close()
			outputWrite.Close()
			diagnostics.Close()
			identity := launchOwner.Child()
			fd, err := identity.NetworkForJob(job)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { fd.Close() })
			return identity, nil, inputWrite, bufio.NewReaderSize(outputRead, 4096), fd
		}
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMeasuredRouteFixtureHelper$")
		cmd.Env = []string{"PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1", "PROVENANCE_RETAINED_HELPER=holder"}
		var ready, readyWriter *os.File
		if sentry {
			cmd = exec.CommandContext(ctx, "/proc/self/fd/5", MeasuredNetworkChildCommand, job, strconv.Itoa(int(uid)), strconv.Itoa(int(uid)), strconv.Itoa(int(uid+1)), strconv.Itoa(int(uid+1)), privateRoot, lease.Snapshot().RootFS.SHA256, "embedded-executable")
			cmd.Env = []string{"PATH=/usr/bin:/bin"}
			for i, path := range []string{lease.RootPath(), lease.SandboxPath(), lease.RunnerPath(), lease.ImagePath(), lease.LoopPath(), "/proc/self/ns/net", "/proc/self/ns/mnt"} {
				flags := os.O_RDONLY
				if i == 0 {
					flags = unix.O_PATH | unix.O_DIRECTORY
				}
				file, err := os.OpenFile(path, flags, 0)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { file.Close() })
				cmd.ExtraFiles = append(cmd.ExtraFiles, file)
			}
			gate, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			release = writer
			t.Cleanup(func() { gate.Close(); writer.Close() })
			cmd.ExtraFiles = append(cmd.ExtraFiles, gate)
			ready, readyWriter, err = os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ready.Close(); readyWriter.Close() })
			cmd.ExtraFiles = append(cmd.ExtraFiles, readyWriter)
		}
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		var diagnostics bytes.Buffer
		cmd.Stderr = &diagnostics
		output, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNET | unix.CLONE_NEWNS,
			UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(uid), Size: 1}, {ContainerID: 65534, HostID: int(uid + 1), Size: 1}},
			GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(uid), Size: 1}, {ContainerID: 65534, HostID: int(uid + 1), Size: 1}},
			GidMappingsEnableSetgroups: false, Credential: &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL,
			UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
		if sentry {
			cmd.SysProcAttr.CgroupFD = int(jobScopeFD.Fd())
		}
		if err := cmd.Start(); err != nil {
			t.Fatal("native fixture child unavailable", err)
		}
		t.Cleanup(func() {
			input.Close()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if t.Failed() {
				t.Logf("disposable child diagnostic: %.4096s", diagnostics.Bytes())
			}
		})
		if sentry {
			readyWriter.Close()
			if !awaitMeasuredNetworkToken(ready, time.Now().Add(5*time.Second), 'r') {
				t.Fatal("measured child initialization readiness missing")
			}
		}
		reader := bufio.NewReaderSize(output, 4096)
		if !sentry {
			line, err := reader.ReadString('\n')
			if err != nil || line != "ready\n" {
				t.Fatal("native holder readiness unavailable")
			}
		}
		identity, err := np.RetainMappedChild(job, cmd.Process, np.MappedIdentity{UID: uid, GID: uid, OverflowUID: uid + 1, OverflowGID: uid + 1})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { identity.Close() })
		fd, err := identity.NetworkForJob(job)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { fd.Close() })
		return identity, cmd, input, reader, fd
	}
	routerContext, cancelRouter := context.WithCancel(ctx)
	t.Cleanup(cancelRouter)
	routerOwner, err := StartRouterOwner(routerContext, specification, journal, lease, np.MappedIdentity{UID: 65530, GID: 65530, OverflowUID: 65531, OverflowGID: 65531})
	if routerOwner != nil {
		t.Cleanup(func() {
			if routerOwner.Close(context.Background()) != nil {
				t.Error("router scope cleanup")
			}
		})
	}
	if err != nil {
		t.Fatal("journaled router launch", err)
	}
	assertRouterThreadsUnprivileged(t, routerOwner)
	router := routerOwner.Child()
	checkParentForwarding()
	routerFD, err := router.NetworkForJob(job)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { routerFD.Close() })
	workload, guest, guestInput, guestOutput, jobFD := child(65532, true)
	if authorityMode == "owned-gated-startup" {
		if err := launchOwner.Close(ctx); err != nil {
			t.Fatal("gated startup cleanup", err)
		}
		if err := launchOwner.Wait(ctx); err == nil || ctx.Err() != nil {
			t.Fatal("unreleased child reported success or timed out", err)
		}
		if _, err := guestOutput.ReadByte(); err != io.EOF {
			t.Fatal("unreleased child produced guest output", err)
		}
		if router.Validate(job) != nil {
			t.Fatal("gated workload cleanup killed router")
		}
		cancelRouter()
		select {
		case <-routerOwner.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("router cancellation did not end holder")
		}
		if routerOwner.Close(context.Background()) != nil || router.Validate(job) == nil {
			t.Fatal("cancelled router scope cleanup")
		}
		return
	}
	wanFD, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal("disposable host network descriptor")
	}
	t.Cleanup(func() { wanFD.Close() })
	if authorityMode == "owned-launch" {
		probe, err := np.CreatePrivateJobLink(ctx, job, router, workload, tools)
		if probe != nil {
			t.Cleanup(func() {
				if probe.Close(context.Background()) != nil {
					t.Error("link refusal probe cleanup")
				}
			})
		}
		if err != nil {
			t.Fatal("link refusal probe", err)
		}
		raw, err := execute(routerFD, tools.IP, "-j", "link", "show", "dev", "job0")
		var rows []struct {
			Alias string `json:"ifalias"`
		}
		if err != nil || json.Unmarshal(raw, &rows) != nil || len(rows) != 1 || rows[0].Alias == "" {
			t.Fatal("link alias fixture")
		}
		if _, err := execute(routerFD, tools.IP, "link", "set", "dev", "job0", "alias", "foreign-fixture"); err != nil {
			t.Fatal(err)
		}
		if probe.Validate(ctx) == nil || probe.Close(ctx) == nil {
			t.Fatal("changed link granted validation or deletion")
		}
		if _, err := execute(routerFD, tools.IP, "link", "set", "dev", "job0", "alias", rows[0].Alias); err != nil {
			t.Fatal("foreign link was deleted")
		}
		if probe.Validate(ctx) == nil || probe.Close(ctx) != nil {
			t.Fatal("link refusal resumed or could not clean original identity")
		}
		for _, drift := range []struct {
			name            string
			change, restore []string
		}{
			{"default-route", []string{"route", "del", "default"}, []string{"route", "add", "default", "via", "10.0.1.1", "dev", "eth0"}},
			{"ipv6-address", []string{"-6", "addr", "del", "fd00:1::2/64", "dev", "eth0"}, []string{"-6", "addr", "add", "fd00:1::2/64", "dev", "eth0", "nodad"}},
			{"permanent-neighbor", []string{"neigh", "del", "10.0.1.1", "dev", "eth0"}, nil},
			{"extra-interface", []string{"link", "add", "bypass", "type", "dummy"}, []string{"link", "delete", "bypass"}},
		} {
			probe, err := np.CreatePrivateJobLink(ctx, job, router, workload, tools)
			if probe != nil {
				t.Cleanup(func() {
					if probe.Close(context.Background()) != nil {
						t.Error("layout probe cleanup")
					}
				})
			}
			if err != nil || probe.ValidatePrepared(ctx) != nil {
				t.Fatal("layout probe creation", drift.name, err)
			}
			if _, err := execute(jobFD, tools.IP, drift.change...); err != nil {
				t.Fatal("layout drift fixture", drift.name)
			}
			if probe.ValidatePrepared(ctx) == nil {
				t.Fatal("layout drift admitted", drift.name)
			}
			if drift.restore != nil {
				if _, err := execute(jobFD, tools.IP, drift.restore...); err != nil {
					t.Fatal("layout restoration fixture", drift.name)
				}
				if probe.ValidatePrepared(ctx) == nil || probe.Validate(ctx) == nil {
					t.Fatal("restored layout resumed", drift.name)
				}
			}
			if probe.Close(ctx) != nil {
				t.Fatal("layout drift cleanup", drift.name)
			}
		}
	}
	privateLink, err := np.CreatePrivateJobLink(ctx, job, router, workload, tools)
	if privateLink != nil {
		t.Cleanup(func() {
			if privateLink.Close(context.Background()) != nil {
				t.Error("owned private link cleanup")
			}
		})
	}
	if err != nil {
		t.Fatal("owned private link creation", err)
	}
	if err := privateLink.ValidatePrepared(ctx); err != nil {
		t.Fatal("private link identity", err)
	}
	if unexpected, err := np.CreatePrivateJobLink(ctx, job, router, workload, tools); unexpected != nil || err == nil {
		t.Fatal("existing link adopted")
	}
	scoped := func(fd *os.File, args ...string) []byte {
		t.Helper()
		raw, err := execute(fd, tools.IP, args...)
		if err != nil {
			t.Fatal("native topology setup failed", args)
		}
		return raw
	}
	statePath := "/state-input/uplink-journal"
	if err := os.Mkdir(statePath, 0700); err != nil && !os.IsExist(err) {
		t.Fatal("uplink state fixture")
	}
	uplinkState, err := os.Open(statePath)
	if err != nil {
		t.Fatal("uplink state descriptor")
	}
	uplinkJournal, err := np.OpenHostUplinkJournal(uplinkState, tools)
	uplinkState.Close()
	if err != nil {
		t.Fatal("host uplink journal", err)
	}
	t.Cleanup(func() {
		if uplinkJournal.Close() != nil {
			t.Error("uplink journal close")
		}
	})
	if err := uplinkJournal.Recover(ctx); err != nil {
		t.Fatal("host uplink recovery", err)
	}
	if authorityMode == "owned-launch" {
		testMeasuredUplinkRefusals(t, ctx, uplinkJournal, privateLink, specification, tools, wanFD, executeContext)
	}
	uplink, err := uplinkJournal.Create(ctx, specification, privateLink)
	if uplink != nil {
		t.Cleanup(func() {
			if uplink.Close(context.Background()) != nil {
				t.Error("host uplink cleanup")
			}
		})
	}
	if err != nil || uplink.Validate(ctx) != nil {
		t.Fatal("host uplink creation", err)
	}
	if authorityMode == "uplink-crash" {
		os.Exit(73)
	}
	for _, address := range []string{"1.1.1.1/32", "1.0.0.1/32", "169.254.169.254/32", "2606:4700:4700::1111/128", "2606:4700:4700::1001/128"} {
		args := []string{"addr", "add", address, "dev", "lo"}
		if address[0] == '2' {
			args = append(args, "nodad")
		}
		scoped(wanFD, args...)
		t.Cleanup(func() {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			remove := []string{"addr", "del", address, "dev", "lo"}
			if _, err := executeContext(cleanupContext, wanFD, tools.IP, remove...); err != nil {
				t.Error("synthetic host address cleanup")
			}
		})
	}
	helper := func(fd *os.File, mode string) (*exec.Cmd, *bufio.Reader) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "/proc/self/fd/4")
		cmd.Args = []string{"nsenter", "-F", "--preserve-credentials", "-n/proc/self/fd/3", "--", "/proc/self/fd/5", "-test.run=^TestMeasuredRouteFixtureHelper$", "-test.timeout=60s"}
		cmd.ExtraFiles = []*os.File{fd, tools.NSenter.File, self.File}
		cmd.Env = []string{"PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1", "PROVENANCE_RETAINED_HELPER=" + mode}
		output, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Start() != nil {
			t.Fatal("native helper unavailable")
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd, bufio.NewReaderSize(output, 4096)
	}
	server, serverOutput := helper(wanFD, "host-uplink-server")
	if read(serverOutput)["serverReady"] != true {
		t.Fatal("native server not ready")
	}
	binder, err := np.NewV2Binder(job, policyRaw, sha256.Sum256(policyRaw), np.LocalV2Boundary{Maximum: proto.Clone(policy.NetworkV2).(*runnerv1.NetworkPolicyV2), SensitiveNetworks: []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}, MaximumTTL: time.Minute}, measuredResolver{})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := binder.Resolve(ctx, "fixture.example.com")
	if err != nil {
		t.Fatal(err)
	}
	route, err := np.NewRetainedRoute(job, router, workload, tools)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { route.Close() })
	err = guard.Start(ctx, []np.Binding{binding}, route)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if guard.Close() != nil {
			t.Error("native Sentry route cleanup failed")
		}
	})
	if err := lease.Validate(); err != nil {
		t.Fatal(err)
	}
	if lease.ValidateChildObjects(workload, job, privateRoot) == nil {
		t.Fatal("gated runner mistaken for running measured sandbox")
	}
	resources, err := np.RetainResources(specification, workload, jobScopeFD)
	if err != nil {
		t.Fatal("actual pre-launch cgroup enforcement", err)
	}
	t.Cleanup(func() { resources.Close() })
	if err := resources.ValidateForChild(specification, workload); err != nil {
		t.Fatal(err)
	}
	// Refuse real kernel limits above a frozen policy, without modifying even
	// this disposable container's cgroup controls.
	for _, kind := range []string{"cpu", "memory", "processes"} {
		lower := proto.Clone(specification).(*runnerv1.JobSpecification)
		switch kind {
		case "cpu":
			lower.EffectivePolicy.Resources.CpuMillis = 1000
		case "memory":
			lower.EffectivePolicy.Resources.MemoryBytes = 512 << 20
		case "processes":
			lower.EffectivePolicy.Resources.ProcessCount = 128
		}
		digest, err := np.EffectivePolicyV2SHA256(lower.EffectivePolicy)
		if err != nil {
			t.Fatal(err)
		}
		lower.Hashes.Policy.Value = digest[:]
		if unexpected, err := np.RetainResources(lower, workload, jobScopeFD); err == nil {
			unexpected.Close()
			t.Fatal("kernel resource limit above original policy accepted", kind)
		}
	}
	probe, err := np.RetainResources(specification, workload, jobScopeFD)
	if err != nil {
		t.Fatal(err)
	}
	wrong := proto.Clone(specification).(*runnerv1.JobSpecification)
	wrong.Attempt.AttemptId = "70000000-0000-4000-8000-000000000001"
	if probe.Validate(wrong) == nil || probe.Validate(specification) == nil {
		t.Fatal("resource proof resumed after owner mismatch")
	}
	if probe.Close() != nil || workload.Validate(job) != nil {
		t.Fatal("closing resource proof killed or invalidated owned child")
	}
	for _, foreign := range []*np.ChildNamespaces{nil, router} {
		probe, err := np.RetainResources(specification, workload, jobScopeFD)
		if err != nil {
			t.Fatal(err)
		}
		if probe.ValidateForChild(specification, foreign) == nil || probe.ValidateForChild(specification, workload) == nil || probe.Validate(specification) == nil {
			t.Fatal("resource proof resumed after exact child mismatch")
		}
		if probe.Close() != nil || workload.Validate(job) != nil || router.Validate(job) != nil || resources.ValidateForChild(specification, workload) != nil {
			t.Fatal("foreign resource proof affected independently owned live resources")
		}
	}
	if err := guard.ObserveInstalledForChild(ctx, specification, workload); err != nil {
		t.Fatal("pre-launch kernel observation", err)
	}
	if authorityMode == "journal-refusal" || authorityMode == "bundle-refusal" || authorityMode == "prepared-refusal" || authorityMode == "link-refusal" || authorityMode == "layout-refusal" || authorityMode == "uplink-refusal" {
		if authorityMode == "uplink-refusal" {
			if launchOwner.Release(ctx, privateLink, nil) == nil {
				t.Fatal("missing host uplink proof opened gate")
			}
		} else if authorityMode == "layout-refusal" {
			scoped(jobFD, "route", "del", "default")
			if launchOwner.Release(ctx, privateLink, uplink) == nil {
				t.Fatal("damaged layout opened gate")
			}
			scoped(jobFD, "route", "add", "default", "via", "10.0.1.1", "dev", "eth0")
		} else if authorityMode == "link-refusal" {
			if launchOwner.Release(ctx, nil, uplink) == nil {
				t.Fatal("missing link proof opened gate")
			}
		} else if authorityMode == "prepared-refusal" {
			if os.Chmod(filepath.Join(bundle, "config.json"), 0644) != nil {
				t.Fatal("prepared configuration drift fixture")
			}
		} else {
			journalPath := "/state-input/journal"
			if authorityMode == "bundle-refusal" {
				journalPath = "/state-input/bundle-journal"
			}
			entries, err := os.ReadDir(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			changed := 0
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".owned.json") {
					if authorityMode == "journal-refusal" {
						var record struct {
							ScopeDev uint64 `json:"scopeDev"`
							ScopeIno uint64 `json:"scopeIno"`
						}
						var scopeStat unix.Stat_t
						raw, err := os.ReadFile(filepath.Join(journalPath, entry.Name()))
						if err != nil || json.Unmarshal(raw, &record) != nil || unix.Fstat(int(jobScopeFD.Fd()), &scopeStat) != nil {
							t.Fatal("owned scope record selection")
						}
						if record.ScopeDev != uint64(scopeStat.Dev) || record.ScopeIno != scopeStat.Ino {
							continue
						}
					}
					if err := os.WriteFile(filepath.Join(journalPath, entry.Name()), []byte("{}\n"), 0600); err != nil {
						t.Fatal(err)
					}
					changed++
				}
			}
			if changed != 1 {
				t.Fatal("expected one owned synthetic journal record")
			}
		}
		if launchOwner.Release(ctx, privateLink, uplink) == nil {
			t.Fatal("corrupt journal opened gate")
		}
		if err := launchOwner.Wait(ctx); err == nil || ctx.Err() != nil {
			t.Fatal("refused gated child not terminated", err)
		}
		if _, err := guestOutput.ReadByte(); err != io.EOF {
			t.Fatal("refused child produced guest output", err)
		}
		if launchOwner.Close(context.Background()) != nil || !cleanupScope() || guard.Close() != nil || server.Process.Signal(syscall.Signal(0)) != nil {
			t.Fatal("refused child cleanup failed")
		}
		return
	}
	if launchOwner != nil {
		if err := launchOwner.Release(ctx, privateLink, uplink); err != nil {
			t.Fatal("owned launch gate", err)
		}
	} else {
		if privateLink.ValidatePrepared(ctx) != nil {
			t.Fatal("fixture pre-exec layout")
		}
		if _, err := release.Write([]byte("s")); err != nil {
			t.Fatal(err)
		}
		if err := release.Close(); err != nil {
			t.Fatal(err)
		}
	}
	checks := read(guestOutput)
	if len(checks) != 15 {
		t.Fatal("native guest packet checks missing")
	}
	for _, name := range []string{"nonRootGuest", "tcp4", "tcp6", "udp4", "udp6", "unbound4", "unbound6", "metadata", "wrongPort", "wrongProtocol", "workspaceQuota", "temporaryQuota", "rootReadOnly", "inputsReadOnly", "privateWorkingDirectory"} {
		if checks[name] != true {
			t.Fatal("native guest packet check failed")
		}
	}
	if authorityMode == "owned-normal" {
		if err := launchOwner.Wait(ctx); err != nil {
			t.Fatal("normal owned execution", err)
		}
		if guard.CheckJob(specification) != nil {
			t.Fatal("normal completion manufactured authority loss")
		}
		if guard.Close() != nil || !cleanupScope() || lease.Validate() != nil || server.Process.Signal(syscall.Signal(0)) != nil {
			t.Fatal("normal owned cleanup incomplete")
		}
		for _, fd := range []*os.File{routerFD, jobFD, wanFD} {
			raw, err := execute(fd, tools.NFT, "-j", "list", "tables")
			var tables struct {
				Items []map[string]json.RawMessage `json:"nftables"`
			}
			if err != nil || json.Unmarshal(raw, &tables) != nil {
				t.Fatal("normal route cleanup inspection", err)
			}
			for _, item := range tables.Items {
				if _, ok := item["table"]; ok {
					t.Fatal("normal route table remains")
				}
			}
		}
		return
	}
	if read(guestOutput)["phase"] != "flows-ready" {
		t.Fatal("native persistent guest flows unavailable")
	}
	if err := privateLink.Validate(ctx); err != nil {
		t.Fatal("live private link changed", err)
	}
	if err := uplink.Validate(ctx); err != nil {
		t.Fatal("live host uplink changed", err)
	}
	if err := lease.ValidateChildObjects(workload, job, privateRoot); err != nil {
		t.Fatal("live sandbox objects do not match measured lease", err)
	}
	if lease.ValidateChildObjects(router, job, privateRoot) == nil || lease.ValidateChildObjects(nil, job, privateRoot) == nil || lease.ValidateChildObjects(workload, job, bundle+"/inputs") == nil {
		t.Fatal("foreign runtime objects accepted")
	}
	if err := resources.ValidateForChild(specification, workload); err != nil {
		t.Fatal("live runtime left original resource boundary", err)
	}
	observation, err := lease.ObserveNetwork(ctx, specification, workload, privateRoot, resources, guard, privateLink, uplink)
	if launchOwner != nil {
		observation, err = launchOwner.ObserveRuntime(ctx)
	}
	if err != nil {
		t.Fatal("live network runtime observation", err)
	}
	proof, err := terminalevidence.BuildObservedNetwork(evidenceContext, "runner-fixture", nil, observation)
	if err != nil || terminalevidence.ValidateFrozenV2(proof, specification, "runner-fixture") != nil || !bytes.Contains(proof.GetCanonicalJson(), []byte(`"networkMode":"allowlist"`)) || !bytes.Contains(proof.GetCanonicalJson(), []byte(`"completeness":"partial"`)) {
		t.Fatal("measured network terminal evidence", err)
	}
	unsealed, err := observation.SnapshotFor(specification.Lease, specification.Attempt, specification.Hashes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := terminalevidence.Build(evidenceContext, "runner-fixture", nil, &unsealed); err == nil {
		t.Fatal("unsealed projection minted new evidence")
	}
	foreignEvidenceJob := proto.Clone(specification).(*runnerv1.JobSpecification)
	foreignEvidenceJob.Attempt.AttemptId = "70000000-0000-4000-8000-000000000002"
	foreignContext, err := terminalevidence.NewContextV2(foreignEvidenceJob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := terminalevidence.BuildObservedNetwork(foreignContext, "runner-fixture", nil, observation); err == nil {
		t.Fatal("observed runtime reassigned to another attempt")
	}
	if guard != nil {
		if err := guard.ObserveInstalledForChild(ctx, specification, workload); err != nil {
			t.Fatal("live Sentry authority/kernel observation failed", err)
		}
	}
	// Renew from a real resolver observation while retaining the same Sentry,
	// namespace objects, flow tracking, byte bucket and original wire policy.
	time.Sleep(1100 * time.Millisecond)
	renewals := 1
	if authorityMode == "owned-launch" {
		renewals = 32
	}
	for i := 0; i < renewals; i++ {
		binding, err = binder.Resolve(ctx, "fixture.example.com")
		if err != nil {
			t.Fatal(err)
		}
		err = guard.RefreshDNS(ctx, []np.Binding{binding})
		if err != nil {
			t.Fatal("native DNS renewal failed", i, err)
		}
	}
	{
		if err == nil {
			// Real installed forwarding/DNS deadlines must shorten without
			// replenishing accounting or interrupting still-authorized flows.
			now := time.Now()
			receipt.NetworkAuthorityV2.CheckedAt = timestamppb.New(now)
			receipt.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(20 * time.Second))
			if authorityMode == "expiry" {
				receipt.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(5 * time.Second))
			}
			err = guard.Reconcile(ctx, receipt, features, credentialExpiry)
		}
	}
	if err != nil {
		t.Fatal("native live renewal failed", err)
	}
	if _, err := guestInput.Write([]byte("refresh\n")); err != nil {
		t.Fatal(err)
	}
	if read(guestOutput)["phase"] != "flows-refreshed" {
		t.Fatal("native renewal broke guest flows")
	}
	if guard != nil {
		if err := guard.ObserveInstalledForChild(ctx, specification, workload); err != nil {
			t.Fatal("renewed live Sentry authority/kernel observation failed", err)
		}
	}
	if authorityMode == "expiry" {
		select {
		case <-guard.Done():
		case <-time.After(8 * time.Second):
			t.Fatal("authority expiry required acknowledgement polling")
		}
	} else if authorityMode == "child-mismatch" {
		// Both are real living retained children with the same job identity.
		// The router cannot stand in for the actual measured workload owner.
		if router.Validate(job) != nil || workload.Validate(job) != nil {
			t.Fatal("child mismatch fixture lost its live owners")
		}
		if guard.ObserveInstalledForChild(ctx, specification, router) == nil {
			t.Fatal("same-job foreign child accepted")
		}
		if guard.ObserveInstalledForChild(ctx, specification, workload) == nil {
			t.Fatal("correct child revived failed observation")
		}
	} else {
		receipt.NetworkAuthorityV2.State = runnerv1.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_WITHDRAWN
		receipt.NetworkAuthorityV2.ExpiresAt = nil
		if err := guard.Reconcile(ctx, receipt, features, credentialExpiry); err == nil {
			t.Fatal("authority withdrawal did not stop owner")
		}
	}
	if guard != nil {
		receipt.NetworkAuthorityV2.State = runnerv1.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT
		receipt.NetworkAuthorityV2.CheckedAt = timestamppb.New(time.Now())
		receipt.NetworkAuthorityV2.ExpiresAt = timestamppb.New(time.Now().Add(20 * time.Second))
		if err := guard.Reconcile(ctx, receipt, features, credentialExpiry); err == nil {
			t.Fatal("native withdrawn authority resumed")
		}
	}
	if launchOwner != nil {
		if err := launchOwner.Wait(ctx); err == nil || ctx.Err() != nil {
			t.Fatal("authority loss did not terminate owned runtime", err)
		}
		if err := launchOwner.Close(context.Background()); err != nil {
			t.Fatal("owned runtime cleanup", err)
		}
	} else {
		if _, err := guestInput.Write([]byte("withdraw\n")); err != nil {
			t.Fatal(err)
		}
		if read(guestOutput)["phase"] != "flows-withdrawn" {
			t.Fatal("native withdrawal retained guest flows")
		}
	}
	if server.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("endpoint loss cannot count as withdrawal")
	}
	if err := lease.Validate(); err != nil {
		t.Fatal("retained measured objects changed", err)
	}
	if guest != nil && guest.Wait() != nil {
		t.Fatal("native Sentry guest failed")
	}
	if err := guard.Close(); err != nil {
		t.Fatal("native Sentry cleanup failed", err)
	}
	if err := guard.CheckJob(specification); err == nil {
		t.Fatal("native withdrawn authority accepted job")
	}
	if resumed, err := lease.ObserveNetwork(ctx, specification, workload, privateRoot, resources, guard, privateLink, uplink); resumed != nil || err == nil {
		t.Fatal("withdrawn runtime produced a fresh observation")
	}
	historical, err := terminalevidence.BuildObservedNetwork(evidenceContext, "runner-fixture", nil, observation)
	if err != nil || !bytes.Equal(historical.GetCanonicalJson(), proof.GetCanonicalJson()) {
		t.Fatal("historical observation changed during cleanup")
	}
	var tables struct {
		Items []map[string]json.RawMessage `json:"nftables"`
	}
	for _, fd := range []*os.File{routerFD, jobFD, wanFD} {
		raw, err := execute(fd, tools.NFT, "-j", "list", "tables")
		if err != nil || json.Unmarshal(raw, &tables) != nil {
			t.Fatal("native cleanup inspection failed")
		}
		for _, item := range tables.Items {
			if _, ok := item["table"]; ok {
				t.Fatal("native owned table remains")
			}
		}
	}
	if !cleanupScope() {
		t.Fatal("exclusive cleanup incomplete")
	}
	if fresh, err := jobScope.LaunchFD(specification); fresh != nil || err == nil {
		t.Fatal("cleaned Sentry scope resumed")
	}
	if router.Validate(job) != nil {
		t.Fatal("workload cleanup killed independent router")
	}
	if uplink.Close(context.Background()) != nil || uplink.Close(context.Background()) != nil {
		t.Fatal("host uplink retirement")
	}
	if privateLink.Close(context.Background()) != nil || privateLink.Close(context.Background()) != nil {
		t.Fatal("private link retirement")
	}
	if err := routerOwner.Close(context.Background()); err != nil {
		t.Fatal("journaled router cleanup", err)
	}
	if router.Validate(job) == nil || routerOwner.Close(context.Background()) != nil {
		t.Fatal("router cleanup was not terminal and idempotent")
	}
	if server.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("Sentry cleanup killed external endpoint")
	}
}

type measuredResolver struct{}

func (measuredResolver) Exchange(_ context.Context, raw []byte) ([]byte, error) {
	var q dnsmessage.Message
	if err := q.Unpack(raw); err != nil {
		return nil, err
	}
	if len(q.Questions) != 1 {
		return nil, fmt.Errorf("fixture question required")
	}
	question := q.Questions[0]
	q.Response = true
	header := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 120}
	if question.Type == dnsmessage.TypeA {
		q.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.AResource{A: netip.MustParseAddr("1.1.1.1").As4()}}}
	} else {
		q.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1111").As16()}}}
	}
	return q.Pack()
}
