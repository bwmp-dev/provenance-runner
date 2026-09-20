//go:build linux

package networkpolicy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRetainedRouteFixtureHelper(t *testing.T) {
	mode := os.Getenv("PROVENANCE_RETAINED_HELPER")
	if mode == "" {
		t.Skip("disposable retained helper only")
	}
	if os.Getuid() != 0 || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		os.Exit(2)
	}
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		os.Exit(2)
	}
	parent, err := os.Stat("/proc/1/ns/net")
	if err != nil || os.SameFile(current, parent) {
		os.Exit(2)
	}
	if mode == "forward" {
		for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
			if os.WriteFile(path, []byte("1\n"), 0600) != nil {
				os.Exit(2)
			}
		}
		os.Exit(0)
	}
	if mode != "server" {
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

func TestRetainedRouteSentryActuation(t *testing.T) {
	testRetainedRouteSentryActuation(t, "", runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST)
}

func TestAuthorityRouteSentryWithdrawal(t *testing.T) {
	testRetainedRouteSentryActuation(t, "withdrawal", runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST)
}

func TestAuthorityRouteSentryExpiry(t *testing.T) {
	testRetainedRouteSentryActuation(t, "expiry", runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST)
}

func TestRestrictedAuthorityRouteSentryWithdrawal(t *testing.T) {
	testRetainedRouteSentryActuation(t, "withdrawal", runnerv1.NetworkMode_NETWORK_MODE_RESTRICTED)
}

func TestRestrictedAuthorityRouteSentryExpiry(t *testing.T) {
	testRetainedRouteSentryActuation(t, "expiry", runnerv1.NetworkMode_NETWORK_MODE_RESTRICTED)
}

func testRetainedRouteSentryActuation(t *testing.T, authorityMode string, networkMode runnerv1.NetworkMode) {
	t.Helper()
	if os.Getenv("PROVENANCE_DISPOSABLE_SENTRY_FIXTURE") != "1" {
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
	// view. The helper below writes forwarding solely in the retained router net.
	if unix.Mount("proc", "/proc", "proc", 0, "") != nil {
		t.Fatal("disposable proc view unavailable")
	}
	t.Cleanup(func() {
		if unix.Unmount("/proc", 0) != nil {
			t.Error("disposable proc cleanup failed")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	const job = "10000000-0000-4000-8000-000000000001"
	load := func(path string) ProtectedRouteTool {
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
		return ProtectedRouteTool{File: f, SHA256: [32]byte(h.Sum(nil))}
	}
	tools := RouteTools{NSenter: load("nsenter"), NFT: load("nft"), IP: load("ip")}
	self := load(os.Args[0])
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
	child := func(uid uint32, sentry bool) (*ChildNamespaces, *exec.Cmd, io.WriteCloser, *bufio.Reader, *os.File) {
		t.Helper()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMappedChildNamespaceProcess$")
		cmd.Env = []string{"PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1", "PROVENANCE_NAMESPACE_TEST_CHILD=holder"}
		if sentry {
			cmd = exec.CommandContext(ctx, "/usr/local/bin/network-sentry-fixture", "child")
			cmd.Env = []string{"PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1"}
		}
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		var diagnostics routeOutput
		cmd.Stderr = &diagnostics
		output, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNET | unix.CLONE_NEWNS,
			UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(uid), Size: 1}, {ContainerID: 65534, HostID: int(uid + 1), Size: 1}},
			GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(uid), Size: 1}, {ContainerID: 65534, HostID: int(uid + 1), Size: 1}},
			GidMappingsEnableSetgroups: false, Credential: &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL}
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
		reader := bufio.NewReaderSize(output, 4096)
		if !sentry {
			line, err := reader.ReadString('\n')
			if err != nil || line != "ready\n" {
				t.Fatal("native holder readiness unavailable")
			}
		}
		identity, err := RetainMappedChild(job, cmd.Process, MappedIdentity{UID: uid, GID: uid, OverflowUID: uid + 1, OverflowGID: uid + 1})
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
	router, _, _, _, routerFD := child(65530, false)
	workload, guest, guestInput, guestOutput, jobFD := child(65532, true)
	_, wan, _, _, wanFD := child(65528, false)
	scoped := func(fd *os.File, args ...string) []byte {
		t.Helper()
		executor := &RetainedRoute{network: fd, tools: tools}
		raw, err := executor.execute(ctx, tools.IP, "", args...)
		if err != nil {
			t.Fatal("native topology setup failed", args)
		}
		return raw
	}
	for _, pair := range []struct {
		name, peer string
		pid        int
	}{{"job0", "eth0", guest.Process.Pid}, {"wan0", "eth0", wan.Process.Pid}} {
		scoped(routerFD, "link", "add", pair.name, "type", "veth", "peer", "name", "newpeer")
		scoped(routerFD, "link", "set", "newpeer", "netns", strconv.Itoa(pair.pid))
		peerFD := jobFD
		if pair.name == "wan0" {
			peerFD = wanFD
		}
		scoped(peerFD, "link", "set", "newpeer", "name", pair.peer)
	}
	for _, item := range []struct {
		fd          *os.File
		dev, v4, v6 string
	}{{jobFD, "eth0", "10.0.1.2", "fd00:1::2"}, {routerFD, "job0", "10.0.1.1", "fd00:1::1"}, {routerFD, "wan0", "10.0.2.1", "fd00:2::1"}, {wanFD, "eth0", "10.0.2.2", "fd00:2::2"}} {
		scoped(item.fd, "link", "set", "lo", "up")
		scoped(item.fd, "addr", "add", item.v4+"/24", "dev", item.dev)
		scoped(item.fd, "-6", "addr", "add", item.v6+"/64", "dev", item.dev, "nodad")
		scoped(item.fd, "link", "set", item.dev, "up")
	}
	mac := func(fd *os.File, dev string) string {
		var rows []struct {
			Address string `json:"address"`
		}
		if json.Unmarshal(scoped(fd, "-j", "link", "show", dev), &rows) != nil || len(rows) != 1 {
			t.Fatal("native peer identity unavailable")
		}
		return rows[0].Address
	}
	for _, item := range []struct {
		fd, peer             *os.File
		dev, peerdev, v4, v6 string
	}{{jobFD, routerFD, "eth0", "job0", "10.0.1.1", "fd00:1::1"}, {routerFD, jobFD, "job0", "eth0", "10.0.1.2", "fd00:1::2"}, {routerFD, wanFD, "wan0", "eth0", "10.0.2.2", "fd00:2::2"}, {wanFD, routerFD, "eth0", "wan0", "10.0.2.1", "fd00:2::1"}} {
		for _, address := range []string{item.v4, item.v6} {
			scoped(item.fd, "neigh", "replace", address, "lladdr", mac(item.peer, item.peerdev), "nud", "permanent", "dev", item.dev)
		}
	}
	for _, item := range []struct {
		fd     *os.File
		v4, v6 string
	}{{jobFD, "10.0.1.1", "fd00:1::1"}, {routerFD, "10.0.2.2", "fd00:2::2"}, {wanFD, "10.0.2.1", "fd00:2::1"}} {
		scoped(item.fd, "route", "add", "default", "via", item.v4)
		scoped(item.fd, "-6", "route", "add", "default", "via", item.v6)
	}
	for _, address := range []string{"1.1.1.1/32", "1.0.0.1/32", "169.254.169.254/32", "2606:4700:4700::1111/128", "2606:4700:4700::1001/128"} {
		args := []string{"addr", "add", address, "dev", "lo"}
		if address[0] == '2' {
			args = append(args, "nodad")
		}
		scoped(wanFD, args...)
	}
	helper := func(fd *os.File, mode string) (*exec.Cmd, *bufio.Reader) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "/proc/self/fd/4")
		cmd.Args = []string{"nsenter", "-F", "--preserve-credentials", "-n/proc/self/fd/3", "--", "/proc/self/fd/5", "-test.run=^TestRetainedRouteFixtureHelper$", "-test.timeout=60s"}
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
	forward, _ := helper(routerFD, "forward")
	if forward.Wait() != nil {
		t.Fatal("owned forwarding setup failed")
	}
	server, serverOutput := helper(wanFD, "server")
	if read(serverOutput)["serverReady"] != true {
		t.Fatal("native server not ready")
	}
	if os.Mkdir("/fixture", 0755) != nil {
		t.Fatal("fresh Sentry fixture directory unavailable")
	}
	t.Cleanup(func() {
		_ = guest.Process.Kill()
		_ = guest.Wait()
		_ = filepath.WalkDir("/fixture", func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				return os.Chown(path, 0, 0)
			}
			return err
		})
		if os.RemoveAll("/fixture") != nil {
			t.Error("owned Sentry fixture cleanup failed")
		}
	})
	for _, directory := range []string{"bundle", "state"} {
		path := filepath.Join("/fixture", directory)
		if os.Mkdir(path, 0755) != nil {
			t.Fatal("owned Sentry directory setup failed")
		}
	}
	spec := map[string]any{"ociVersion": "1.0.2", "root": map[string]any{"path": "/guestroot", "readonly": true}, "mounts": []any{},
		"process": map[string]any{"terminal": false, "user": map[string]any{"uid": 65532, "gid": 65532}, "args": []string{"/smoke", "probe-lifecycle"}, "env": []string{"PATH=/"}, "cwd": "/", "noNewPrivileges": true,
			"capabilities": map[string]any{"bounding": []string{}, "effective": []string{}, "inheritable": []string{}, "permitted": []string{}, "ambient": []string{}}, "rlimits": []any{map[string]any{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}}},
		"linux": map[string]any{"namespaces": []any{map[string]string{"type": "pid"}, map[string]string{"type": "ipc"}, map[string]string{"type": "uts"}, map[string]string{"type": "mount"}, map[string]string{"type": "network", "path": "/proc/self/ns/net"}}}}
	raw, err := json.Marshal(spec)
	if err != nil || os.WriteFile("/fixture/bundle/config.json", raw, 0644) != nil {
		t.Fatal("owned OCI fixture unavailable")
	}
	for _, directory := range []string{"bundle", "state"} {
		if os.Chown(filepath.Join("/fixture", directory), 65532, 65532) != nil {
			t.Fatal("owned Sentry directory ownership unavailable")
		}
	}
	policy := &runnerv1.EffectivePolicy{Sandbox: runnerv1.SandboxKind_SANDBOX_KIND_GVISOR, Requirement: runnerv1.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED,
		Resources: &runnerv1.ResourceLimits{CpuMillis: 2000, MemoryBytes: 2 << 30, DiskBytes: 4 << 30, ProcessCount: 256}, PreparationTimeout: durationpb.New(time.Minute), ExecutionTimeout: durationpb.New(time.Minute), GracefulShutdownTimeout: durationpb.New(10 * time.Second),
		NetworkV2: &runnerv1.NetworkPolicyV2{Mode: networkMode, MaximumConnections: 16, MaximumBytesPerSecond: 65536, Permissions: []*runnerv1.NetworkPermissionV2{{Hostname: "fixture.example.com", Port: 8080, Transport: runnerv1.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP}, {Hostname: "fixture.example.com", Port: 8081, Transport: runnerv1.NetworkTransportV2_NETWORK_TRANSPORT_V2_UDP}}}}
	raw, err = (proto.MarshalOptions{Deterministic: true}).Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	binder, err := NewV2Binder(job, raw, sha256.Sum256(raw), LocalV2Boundary{Maximum: proto.Clone(policy.NetworkV2).(*runnerv1.NetworkPolicyV2), SensitiveNetworks: prefixes("93.184.216.0/24"), MaximumTTL: time.Minute}, responder(nil))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := binder.Resolve(ctx, "fixture.example.com")
	if err != nil {
		t.Fatal(err)
	}
	route, err := NewRetainedRoute(job, router, workload, tools)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { route.Close() })
	var session *RouteSession
	var guard *AuthorityRoute
	var receipt *runnerv1.LeaseReconciliation
	var specification *runnerv1.JobSpecification
	features := []runnerv1.ProtocolFeature{1, 3, 9, 10}
	credentialExpiry := time.Now().Add(2 * time.Minute)
	if authorityMode == "" {
		session, err = StartRoute(ctx, job, []Binding{binding}, route)
	} else {
		now := time.Now()
		digest := sha256.Sum256(raw)
		specification = &runnerv1.JobSpecification{
			Lease:           &runnerv1.LeaseIdentity{JobId: job, LeaseId: "20000000-0000-4000-8000-000000000001", ExecutionId: "30000000-0000-4000-8000-000000000001", ExpiresAt: timestamppb.New(credentialExpiry)},
			Attempt:         &runnerv1.AttemptIdentity{AttemptId: "40000000-0000-4000-8000-000000000001", ReleaseCandidateId: "50000000-0000-4000-8000-000000000001", MatrixEntryId: "60000000-0000-4000-8000-000000000001", AttemptNumber: 1},
			EffectivePolicy: policy, Hashes: &runnerv1.JobHashes{Policy: &runnerv1.Digest{Algorithm: runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}},
		}
		guard, err = NewAuthorityRoute(ctx, specification)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := guard.Close(); err != nil {
				t.Error("authority route cleanup failed", err)
			}
		})
		receipt = &runnerv1.LeaseReconciliation{Lease: specification.Lease, Attempt: specification.Attempt, Status: runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: runnerv1.JobPhase_JOB_PHASE_RUNNING, Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE,
			NetworkAuthorityV2: &runnerv1.NetworkAuthorityV2{Policy: specification.Hashes.Policy, State: runnerv1.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT, CheckedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(40 * time.Second))}}
		if err := guard.Reconcile(ctx, receipt, features, credentialExpiry); err != nil {
			t.Fatal(err)
		}
		err = guard.Start(ctx, []Binding{binding}, route)
		session = guard.route
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if session.Close() != nil {
			t.Error("native Sentry route cleanup failed")
		}
	})
	if _, err := guestInput.Write([]byte("s")); err != nil {
		t.Fatal("native guest barrier failed")
	}
	checks := read(guestOutput)
	if len(checks) != 10 {
		t.Fatal("native guest packet checks missing")
	}
	for _, name := range []string{"nonRootGuest", "tcp4", "tcp6", "udp4", "udp6", "unbound4", "unbound6", "metadata", "wrongPort", "wrongProtocol"} {
		if checks[name] != true {
			t.Fatal("native guest packet check failed")
		}
	}
	if read(guestOutput)["phase"] != "flows-ready" {
		t.Fatal("native persistent guest flows unavailable")
	}
	if guard != nil {
		if err := guard.ObserveInstalled(ctx, specification); err != nil {
			t.Fatal("live Sentry authority/kernel observation failed", err)
		}
	}
	// Renew from a real resolver observation while retaining the same Sentry,
	// namespace objects, flow tracking, byte bucket and original wire policy.
	time.Sleep(1100 * time.Millisecond)
	binding, err = binder.Resolve(ctx, "fixture.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if guard == nil {
		err = session.Refresh(ctx, []Binding{binding})
	} else {
		err = guard.RefreshDNS(ctx, []Binding{binding})
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
		if err := guard.ObserveInstalled(ctx, specification); err != nil {
			t.Fatal("renewed live Sentry authority/kernel observation failed", err)
		}
	}
	if guard == nil {
		if err := session.Withdraw(); err != nil {
			t.Fatal(err)
		}
	} else if authorityMode == "expiry" {
		select {
		case <-guard.Done():
		case <-time.After(8 * time.Second):
			t.Fatal("authority expiry required acknowledgement polling")
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
	if _, err := guestInput.Write([]byte("withdraw\n")); err != nil {
		t.Fatal(err)
	}
	if read(guestOutput)["phase"] != "flows-withdrawn" {
		t.Fatal("native withdrawal retained guest flows")
	}
	if server.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("endpoint loss cannot count as withdrawal")
	}
	if guest.Wait() != nil {
		t.Fatal("native Sentry guest failed")
	}
	if err := session.Close(); err != nil {
		t.Fatal("native Sentry cleanup failed", err)
	}
	if _, err := session.DNS(); err != ErrExpired {
		t.Fatal("native withdrawn route exposed DNS")
	}
	var tables struct {
		Items []map[string]json.RawMessage `json:"nftables"`
	}
	for _, fd := range []*os.File{routerFD, jobFD, wanFD} {
		executor := &RetainedRoute{network: fd, tools: tools}
		raw, err := executor.execute(ctx, tools.NFT, "", "-j", "list", "tables")
		if err != nil || json.Unmarshal(raw, &tables) != nil {
			t.Fatal("native cleanup inspection failed")
		}
		for _, item := range tables.Items {
			if _, ok := item["table"]; ok {
				t.Fatal("native owned table remains")
			}
		}
	}
}
