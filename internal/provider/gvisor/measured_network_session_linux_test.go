//go:build linux

package gvisor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"google.golang.org/protobuf/proto"
)

func TestMeasuredSessionRequiresOwners(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if session, err := startMeasuredSession(ctx, measuredSessionConfig{}); session != nil || err == nil {
			t.Fatal("missing owners admitted")
		}
	}
	var absent *measuredNetworkSession
	if absent.Close(context.Background()) != nil || absent.Release(context.Background()) == nil || absent.Wait(context.Background()) == nil {
		t.Fatal("nil session handling")
	}
	if observation, err := absent.ObserveRuntime(context.Background()); observation != nil || err == nil {
		t.Fatal("nil observation")
	}
	s := &measuredNetworkSession{done: make(chan struct{})}
	if s.Close(context.Background()) != nil || s.Close(context.Background()) != nil || s.Release(context.Background()) == nil || !errors.Is(s.Wait(context.Background()), context.Canceled) {
		t.Fatal("empty session retirement")
	}
}

func testMeasuredSessionFixture(t *testing.T, ctx context.Context, mode string, c measuredSessionConfig, self np.ProtectedRouteTool) {
	t.Helper()
	if err := os.Mkdir("/state-input/uplink-journal", 0700); err != nil && !os.IsExist(err) {
		t.Fatal("session uplink fixture")
	}
	state, err := os.Open("/state-input/uplink-journal")
	if err != nil {
		t.Fatal("session state descriptor")
	}
	c.Uplinks, err = np.OpenHostUplinkJournal(state, c.Tools)
	state.Close()
	if err != nil {
		t.Fatal("session uplink journal")
	}
	t.Cleanup(func() {
		if c.Uplinks.Close() != nil {
			t.Error("session journal closure")
		}
	})
	if c.Uplinks.Recover(ctx) != nil {
		t.Fatal("session journal recovery")
	}
	in, input, err := os.Pipe()
	if err != nil {
		t.Fatal("session input pipe")
	}
	t.Cleanup(func() { in.Close(); input.Close() })
	output, out, err := os.Pipe()
	if err != nil {
		t.Fatal("session output pipe")
	}
	t.Cleanup(func() { output.Close(); out.Close() })
	stderr, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal("session stderr fixture")
	}
	t.Cleanup(func() { stderr.Close() })
	c.Launch.Stdin, c.Launch.Stdout, c.Launch.Stderr = in, out, stderr
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(c.Launch.Job.EffectivePolicy)
	if err != nil {
		t.Fatal("session policy encoding")
	}
	binder, err := np.NewV2Binder(c.Launch.Job.Lease.JobId, raw, sha256.Sum256(raw), np.LocalV2Boundary{Maximum: c.Launch.Job.EffectivePolicy.NetworkV2, SensitiveNetworks: []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}, MaximumTTL: time.Minute}, measuredResolver{})
	if err != nil {
		t.Fatal("session DNS binder")
	}
	binding, err := binder.Resolve(ctx, "fixture.example.com")
	if err != nil {
		t.Fatal("session DNS binding")
	}
	c.Bindings = []np.Binding{binding}
	if mode == "session-startup-refusal" {
		c.Tools.IP = np.ProtectedRouteTool{}
	}
	session, err := startMeasuredSession(ctx, c)
	if session != nil {
		t.Cleanup(func() {
			if session.Close(context.Background()) != nil {
				t.Error("session cleanup")
			}
		})
	}
	in.Close()
	out.Close()
	if mode == "session-startup-refusal" {
		if session == nil || err == nil || !c.Launch.Bundle.retired || session.Close(ctx) != nil || session.Wait(ctx) == nil {
			t.Fatal("partial startup not retired")
		}
		return
	}
	if err != nil {
		t.Fatal("session construction", err)
	}
	assertRouterThreadsUnprivileged(t, session.router)
	host, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal("session host namespace")
	}
	t.Cleanup(func() { host.Close() })
	execute := func(ctx context.Context, args ...string) error {
		cmd := exec.CommandContext(ctx, "/proc/self/fd/4")
		cmd.Args = append([]string{"nsenter", "-F", "--preserve-credentials", "-n/proc/self/fd/3", "--", "/proc/self/fd/5"}, args...)
		cmd.ExtraFiles = []*os.File{host, c.Tools.NSenter.File, c.Tools.IP.File}
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		return cmd.Run()
	}
	for _, address := range []string{"1.1.1.1/32", "1.0.0.1/32", "169.254.169.254/32", "2606:4700:4700::1111/128", "2606:4700:4700::1001/128"} {
		args := []string{"addr", "add", address, "dev", "lo"}
		if strings.Contains(address, ":") {
			args = append(args, "nodad")
		}
		if execute(ctx, args...) != nil {
			t.Fatal("session synthetic endpoint")
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if execute(cleanup, "addr", "del", address, "dev", "lo") != nil {
				t.Error("session synthetic endpoint cleanup")
			}
		})
	}
	server := exec.CommandContext(ctx, "/proc/self/fd/3", "-test.run=^TestMeasuredRouteFixtureHelper$")
	server.ExtraFiles = []*os.File{self.File}
	server.Env = []string{"PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1", "PROVENANCE_RETAINED_HELPER=host-uplink-server"}
	serverOutput, err := server.StdoutPipe()
	if err != nil || server.Start() != nil {
		t.Fatal("session endpoint server")
	}
	t.Cleanup(func() { server.Process.Kill(); server.Wait() })
	read := func(reader *bufio.Reader) map[string]any {
		t.Helper()
		raw, err := reader.ReadSlice('\n')
		var row map[string]any
		if err != nil || json.Unmarshal(raw, &row) != nil {
			t.Fatal("bounded session report missing")
		}
		return row
	}
	if read(bufio.NewReaderSize(serverOutput, 4096))["serverReady"] != true {
		t.Fatal("session server readiness")
	}
	if session.Release(ctx) != nil {
		t.Fatal("session release")
	}
	output.SetReadDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReaderSize(output, 4096)
	checks := read(reader)
	if len(checks) != 15 {
		t.Fatal("session packet checks missing")
	}
	for _, name := range []string{"nonRootGuest", "tcp4", "tcp6", "udp4", "udp6", "unbound4", "unbound6", "metadata", "wrongPort", "wrongProtocol", "workspaceQuota", "temporaryQuota", "rootReadOnly", "inputsReadOnly", "privateWorkingDirectory"} {
		if checks[name] != true {
			t.Fatal("session packet or confinement check failed")
		}
	}
	dnsChecks := read(reader)
	if len(dnsChecks) != 6 {
		t.Fatal("owned DNS checks missing")
	}
	for _, name := range []string{"udpip4", "udpip6", "tcpip4", "tcpip6", "udpUnlistedDenied", "tcpUnlistedDenied"} {
		if dnsChecks[name] != true {
			t.Fatal("owned DNS check failed")
		}
	}
	if mode == "session-router-loss" || mode == "session-dns-loss" {
		if read(reader)["phase"] != "flows-ready" {
			t.Fatal("session flows unavailable")
		}
		if observation, err := session.ObserveRuntime(ctx); observation == nil || err != nil {
			t.Fatal("session runtime observation", err)
		}
		if mode == "session-router-loss" && session.router.Close(ctx) != nil {
			t.Fatal("session router-loss fixture")
		}
		if mode == "session-dns-loss" && session.router.dns.udp.Close() != nil {
			t.Fatal("session DNS-loss fixture")
		}
		if session.Wait(ctx) == nil || ctx.Err() != nil {
			t.Fatal("router loss not propagated")
		}
	} else if session.Wait(ctx) != nil {
		t.Fatal("normal session completion")
	}
	if !c.Launch.Bundle.retired || session.Close(ctx) != nil || session.Release(ctx) == nil {
		t.Fatal("session retirement or no-resume")
	}
	if observation, err := session.ObserveRuntime(ctx); observation != nil || err == nil {
		t.Fatal("retired session observation")
	}
	if c.Uplinks.Recover(ctx) != nil {
		t.Fatal("session host peer survived")
	}
}
