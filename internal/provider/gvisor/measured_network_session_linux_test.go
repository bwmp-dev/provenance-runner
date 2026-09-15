//go:build linux

package gvisor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
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
	c.Boundary, err = newMeasuredLocalBoundary(proto.Clone(c.Launch.Job.EffectivePolicy).(*runnerv1.EffectivePolicy), c.Launch.Mapping, c.RouterMapping, []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}, 4*time.Second)
	if err != nil {
		t.Fatal("session local boundary")
	}
	resolver := &sessionDNSResolverFixture{}
	if mode == "session-preparation-timeout" {
		resolver.blocked.Store(true)
	}
	c.Resolver = resolver
	if mode == "session-paper-guest" || mode == "session-paper-guest-refusal" {
		measuredPaperGuestFixture(t, ctx, mode, c, input, out, output)
		return
	}
	if mode == "session-normal" {
		for _, name := range []string{"local-maximum-refusal", "local-identity-refusal"} {
			t.Run(name, func(t *testing.T) {
				bad := c
				if name == "local-maximum-refusal" {
					maximum := proto.Clone(c.Launch.Job.EffectivePolicy).(*runnerv1.EffectivePolicy)
					maximum.Resources.MemoryBytes--
					bad.Boundary, err = newMeasuredLocalBoundary(maximum, c.Launch.Mapping, c.RouterMapping, c.Boundary.dns.SensitiveNetworks, 4*time.Second)
					if err != nil {
						t.Fatal("negative local maximum")
					}
				} else {
					bad.RouterMapping = c.Launch.Mapping
				}
				refused, err := startMeasuredSession(ctx, bad)
				if refused != nil {
					_ = refused.Close(context.Background())
				}
				if refused != nil || err == nil || c.Launch.Bundle.checkPrepared(c.Launch.Mapping) != nil || c.Launch.Journal.CheckScope(c.Launch.Scope) != nil {
					t.Fatal("local boundary refusal mutated prepared ownership")
				}
			})
		}
	}
	if mode == "session-startup-refusal" {
		c.Tools.IP = np.ProtectedRouteTool{}
	}
	var session *measuredNetworkSession
	var controller *measuredController
	var controlled *measuredControllerJob
	var controllerInput measuredInput
	if mode == "session-normal" || mode == "session-controller-resource-loss" {
		controller, controllerInput = measuredControllerSessionFixture(t, ctx, c)
	}
	retainCleanup := func() {
		if session != nil {
			t.Cleanup(func() {
				if session.Close(context.Background()) != nil {
					t.Error("session cleanup")
				}
			})
		}
	}
	if mode == "session-normal" {
		// Retire the calling OS thread, not the controller process. Owned
		// children must remain alive until their own lifetime is ended.
		finished := make(chan struct{})
		var caller *os.File
		var start func()
		start = func() {
			runtime.LockOSThread() // Deliberately no Unlock: exiting retires it.
			if unix.Gettid() == os.Getpid() {
				// Go parks m0 rather than retiring it. Keep it occupied until
				// the actual caller has run on another locked OS thread.
				go start()
				<-finished
				runtime.UnlockOSThread()
				return
			}
			defer close(finished)
			caller, err = os.Open("/proc/self/task/" + strconv.Itoa(unix.Gettid()))
			if err == nil {
				controlled, err = controller.start(ctx, c.Launch.Job, measuredGuestCommand{Command: "/smoke", Arguments: []string{"probe-confined-dns"}}, []measuredInput{controllerInput}, c.Launch.Authority, in, out, stderr)
				if controlled != nil {
					session = controlled.session
					c.Launch.Bundle = controlled.bundle
					if controlled.bundle != nil {
						c.Launch.Scope = controlled.bundle.scope
					}
				}
			}
		}
		go start()
		<-finished
		retainCleanup()
		if caller != nil {
			defer caller.Close()
			deadline := time.Now().Add(time.Second)
			for {
				fd, probeErr := unix.Openat(int(caller.Fd()), "status", unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if probeErr == unix.ENOENT || probeErr == unix.ESRCH {
					break
				}
				if fd >= 0 {
					unix.Close(fd)
				}
				if probeErr != nil || time.Now().After(deadline) {
					t.Fatal("session caller thread did not retire")
				}
				time.Sleep(time.Millisecond)
			}
		}
	} else {
		if controller != nil {
			controlled, err = controller.start(ctx, c.Launch.Job, measuredGuestCommand{Command: "/smoke", Arguments: []string{"probe-confined-dns-lifecycle"}}, []measuredInput{controllerInput}, c.Launch.Authority, in, out, stderr)
			if controlled != nil {
				session = controlled.session
				c.Launch.Bundle = controlled.bundle
				if controlled.bundle != nil {
					c.Launch.Scope = controlled.bundle.scope
				}
			}
		} else {
			session, err = startMeasuredSession(ctx, c)
		}
		retainCleanup()
	}
	in.Close()
	out.Close()
	if mode == "session-startup-refusal" || mode == "session-preparation-timeout" {
		if session == nil || err == nil || !c.Launch.Bundle.retired || session.Close(ctx) != nil || session.Wait(ctx) == nil {
			t.Fatal("partial startup not retired")
		}
		if mode == "session-preparation-timeout" && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("preparation timeout cause lost")
		}
		return
	}
	if err != nil {
		t.Fatal("session construction", err)
	}
	if controlled != nil {
		t.Run("controller-busy-refusal", func(t *testing.T) {
			if second, err := controller.start(ctx, c.Launch.Job, measuredGuestCommand{Command: "/smoke"}, []measuredInput{controllerInput}, c.Launch.Authority, in, out, stderr); second != nil || err == nil {
				t.Fatal("busy controller admitted another job")
			}
			if controller.resources.Close() == nil || controller.resources.Validate() != nil {
				t.Fatal("active aggregate handle released")
			}
		})
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
	release := session.Release
	if controlled != nil {
		release = controlled.Release
	}
	if release(ctx) != nil {
		t.Fatal("session release")
	}
	const cleanupRefusal = "/state-input/uplink-journal/controller-cleanup-refusal"
	if controlled != nil && mode == "session-normal" {
		foreign, err := os.OpenFile(cleanupRefusal, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("controller cleanup refusal fixture")
		}
		if foreign.Close() != nil {
			t.Fatal("controller cleanup fixture close")
		}
		t.Cleanup(func() {
			if err := os.Remove(cleanupRefusal); err != nil && !os.IsNotExist(err) {
				t.Error("controller cleanup fixture retirement")
			}
		})
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
	if len(dnsChecks) != 10 {
		t.Fatal("owned DNS checks missing")
	}
	for _, name := range []string{"udpip4", "udpip6", "tcpip4", "tcpip6", "udpUnlistedDenied", "tcpUnlistedDenied", "defaultip4", "defaultip6", "defaultUnlistedDenied", "resolverReadOnly"} {
		if dnsChecks[name] != true {
			t.Fatal("owned DNS check failed")
		}
	}
	if mode == "session-router-loss" || mode == "session-dns-loss" || mode == "session-dns-refresh-failure" || mode == "session-execution-timeout" || mode == "session-controller-resource-loss" {
		if read(reader)["phase"] != "flows-ready" {
			t.Fatal("session flows unavailable")
		}
		observe := session.ObserveRuntime
		if controlled != nil {
			observe = controlled.ObserveRuntime
		}
		observation, err := observe(ctx)
		if observation == nil || err != nil {
			t.Fatal("session runtime observation", err)
		}
		if mode == "session-router-loss" {
			t.Run("root-observation-transfer", func(t *testing.T) { measuredRootObservationFixture(t, c.Launch.Job, observation) })
		}
		if mode == "session-router-loss" && session.router.Close(ctx) != nil {
			t.Fatal("session router-loss fixture")
		}
		if mode == "session-dns-loss" && session.router.dns.udp.Close() != nil {
			t.Fatal("session DNS-loss fixture")
		}
		if mode == "session-dns-refresh-failure" {
			resolver.fail.Store(true)
		}
		if mode == "session-controller-resource-loss" {
			limit := strconv.FormatUint(2*c.Boundary.maximum.Resources.MemoryBytes, 10)
			if os.WriteFile(controllerResourceFixturePath+"memory.max", []byte(strconv.FormatUint(2*c.Boundary.maximum.Resources.MemoryBytes+4096, 10)), 0600) != nil {
				t.Fatal("aggregate drift fixture")
			}
			t.Cleanup(func() { os.WriteFile(controllerResourceFixturePath+"memory.max", []byte(limit), 0600) })
		}
		wait := session.Wait
		if controlled != nil {
			wait = controlled.Wait
		}
		waitErr := wait(ctx)
		if waitErr == nil || ctx.Err() != nil {
			t.Fatal("router loss not propagated")
		}
		if mode == "session-execution-timeout" && !errors.Is(waitErr, context.DeadlineExceeded) {
			t.Fatal("execution timeout cause lost")
		}
		if mode == "session-controller-resource-loss" {
			if !errors.Is(waitErr, np.ErrResources) {
				t.Fatal("aggregate loss cause missing", waitErr)
			}
			if os.WriteFile(controllerResourceFixturePath+"memory.max", []byte(strconv.FormatUint(2*c.Boundary.maximum.Resources.MemoryBytes, 10)), 0600) != nil {
				t.Fatal("restore aggregate fixture")
			}
			if controller.resources.Validate() == nil {
				t.Fatal("restored aggregate drift resumed")
			}
		}
	} else {
		wait := session.Wait
		if controlled != nil {
			if session.Wait(ctx) != nil {
				t.Fatal("controller session completion")
			}
			t.Run("controller-cleanup-refusal", func(t *testing.T) {
				short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
				if controlled.Wait(short) == nil {
					t.Fatal("unverified cleanup released controller job")
				}
				controller.mu.Lock()
				held := controller.active == controlled && !controlled.retired
				controller.mu.Unlock()
				if !held {
					t.Fatal("failed cleanup released controller slot")
				}
				if err := os.Remove(cleanupRefusal); err != nil {
					t.Fatal("exact controller fixture retirement", err)
				}
				if controlled.Close(ctx) != nil {
					t.Fatal("controller cleanup retry")
				}
			})
			wait = controlled.Wait
		}
		if wait(ctx) != nil {
			t.Fatal("normal session completion")
		}
	}
	if session.dns.refreshes.Load() == 0 || session.dnsRefreshDone != nil {
		t.Fatal("session DNS renewal or retirement missing")
	}
	if !c.Launch.Bundle.retired || session.Close(ctx) != nil || session.Release(ctx) == nil {
		t.Fatal("session retirement or no-resume")
	}
	if observation, err := session.ObserveRuntime(ctx); observation != nil || err == nil {
		t.Fatal("retired session observation")
	}
	if controlled != nil {
		t.Run("controller-slot-retirement", func(t *testing.T) {
			controller.mu.Lock()
			active := controller.active
			controller.mu.Unlock()
			if active != nil || controlled.Release(ctx) == nil || controller.Close(ctx) != nil {
				t.Fatal("controller slot or old handle survived")
			}
			reopened, err := newMeasuredController(ctx, controller.config)
			if err != nil || reopened == nil {
				t.Fatal("retired controller claim was not reusable", err)
			}
			if reopened.Close(ctx) != nil {
				t.Fatal("reopened controller cleanup")
			}
		})
	}
	if c.Uplinks.Recover(ctx) != nil {
		t.Fatal("session host peer survived")
	}
}
