//go:build linux

package measuredservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/measuredclient"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/provider/gvisor"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		if len(os.Args) == 2 && os.Args[1] == "--version" && os.Getuid() == 0 {
			// Explicit root-pin regression canary, never a JAR interpreter.
			if enabled, err := os.Stat("/tmp/provenance-version-pin-fixture-enabled"); err == nil && enabled.Mode().IsRegular() && enabled.Mode().Perm() == 0400 {
				if _, err := os.Stat("/.dockerenv"); err == nil {
					if os.WriteFile("/tmp/provenance-unexpected-version-invocation", []byte("synthetic version invocation"), 0600) != nil {
						os.Exit(1)
					}
					fmt.Println("runsc version fixture")
					return
				}
			}
		}
		switch os.Args[1] {
		case gvisor.MeasuredNetworkChildCommand:
			os.Exit(gvisor.RunMeasuredNetworkChild(os.Args[2:], os.Stderr))
		case gvisor.RouterChildCommand:
			os.Exit(gvisor.RunRouterChild(os.Args[2:], os.Stderr))
		case "service-client":
			serviceFixtureClient()
			return
		case "service-idle", "service-secrets-enabled", "service-secrets-disabled":
			if len(os.Args) != 3 || os.Getuid() != 65532 || os.Getgid() != 65532 || os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" {
				panic("disposable idle client required")
			}
			conn, err := net.DialTimeout("unixpacket", os.Args[2], time.Second)
			if err != nil {
				panic(err)
			}
			channel, err := cc.New(conn.(*net.UnixConn), 0)
			if err != nil {
				conn.Close()
				panic(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if os.Args[1] == "service-idle" {
				if measuredclient.CheckIdle(ctx, channel) != nil {
					panic("root idle barrier refused after cleanup")
				}
			} else if err := measuredclient.CheckSecrets(ctx, channel); (err == nil) != (os.Args[1] == "service-secrets-enabled") {
				panic("root secret capability does not match actual provisioning")
			}
			return
		}
		if strings.HasPrefix(os.Args[1], "-Xms") {
			// Synthetic Java stand-in only, inside the explicitly prepared
			// measured guest. It never interprets or executes any JAR bytes.
			if os.Getuid() != 65532 || os.Getgid() != 65532 {
				os.Exit(125)
			}
			if value, err := os.ReadFile(ts.Destination + "/license"); err == nil {
				if string(value) != "synthetic-session-secret" || os.WriteFile(ts.Destination+"/license", []byte("changed"), 0444) == nil {
					os.Exit(125)
				}
				clear(value)
				fmt.Println("ROOT_SECRET_READ_ONLY_OK")
			}
			if os.WriteFile("/tmp/provenance-probe-events.ndjson", []byte("{\"syntheticRootService\":true}\n"), 0600) != nil {
				os.Exit(125)
			}
			// Completion must outlive the initial two-second authority grant;
			// the real root route therefore needs the forwarded fresh renewal.
			fmt.Println("ROOT_SERVICE_STARTED")
			// Streaming redaction deliberately holds back enough bytes to
			// detect cross-frame/line secret variants. Supply harmless fixture
			// output beyond that window before waiting for withdrawal.
			fmt.Println(strings.Repeat("fixture-padding-", 8))
			time.Sleep(3 * time.Second)
			fmt.Println("ROOT_SERVICE_OK")
			fmt.Println("synthetic-session-secret")
			return
		}
	}
	os.Exit(m.Run())
}

func serviceFixtureClient() {
	if len(os.Args) != 4 || (os.Args[3] != "complete" && os.Args[3] != "withdraw" && os.Args[3] != "reject-release" && os.Args[3] != "reject-events" && os.Args[3] != "secrets" && os.Args[3] != "secrets-missing" && os.Args[3] != "secrets-expired") || os.Getuid() != 65532 || os.Getgid() != 65532 || os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" {
		panic("disposable service client required")
	}
	read := func(fd uintptr, maximum int64) []byte {
		file := os.NewFile(fd, "service fixture metadata")
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
		if err != nil || int64(len(raw)) > maximum {
			panic("bounded fixture metadata")
		}
		return raw
	}
	request, ack := read(3, cc.MaximumStartBytes), read(4, 16<<10)
	job, _, err := paper.DecodeMeasuredRequest(request)
	if err != nil {
		panic(err)
	}
	// This fixture has the four signed runtime inputs, target and probe plan.
	var files []*os.File
	for fd := uintptr(5); fd < 11; fd++ {
		file := os.NewFile(fd, "service fixture input")
		files = append(files, file)
		defer file.Close()
	}
	conn, err := net.DialTimeout("unixpacket", os.Args[2], 3*time.Second)
	if err != nil {
		panic(err)
	}
	channel, err := cc.New(conn.(*net.UnixConn), 0)
	if err != nil {
		conn.Close()
		panic(err)
	}
	defer channel.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if os.Args[3] == "secrets-missing" || os.Args[3] == "secrets-expired" {
		// Deliberately bypass worker-side secret validation. This fixture
		// exercises the authenticated root's own rejection boundary.
		last, err := cc.SendStart(channel, request, files, time.Now().Add(5*time.Second))
		if err != nil {
			panic("raw secret refusal startup")
		}
		last++
		if channel.Send(cc.Packet{Kind: cc.Reconcile, Sequence: last, Payload: ack}, time.Now().Add(time.Second)) != nil {
			panic("raw secret authority")
		}
		packet, err := channel.AwaitRootObservation(ctx)
		if err != nil {
			panic("raw secret observation")
		}
		if _, err := runtimeidentity.ImportRootObservation(job, packet); err != nil {
			panic("raw secret binding")
		}
		last++
		refusal := cc.Packet{Kind: cc.Release, Sequence: last}
		if os.Args[3] == "secrets-expired" {
			// Canonical header deliberately names an expired delivery. Root
			// must refuse it before asking for any value-bearing descriptors.
			refusal.Kind = cc.SecretDelivery
			refusal.Payload, err = json.Marshal(struct {
				Version         int      `json:"version"`
				Names           []string `json:"names"`
				ExpiresUnixNano int64    `json:"expiresUnixNano"`
			}{1, []string{"license"}, time.Now().Add(-time.Second).UnixNano()})
			if err != nil {
				panic("raw secret header")
			}
		}
		if channel.Send(refusal, time.Now().Add(time.Second)) != nil {
			panic("raw secret refusal packet")
		}
		if packet, err := channel.Receive(time.Now().Add(5 * time.Second)); err == nil {
			for _, file := range packet.Files {
				file.Close()
			}
			panic("root emitted output after refused secret delivery")
		}
		return
	}
	update, err := np.DecodeAuthorityUpdate(ack)
	if err != nil {
		panic(err)
	}
	guard, err := np.NewAuthorityRoute(ctx, job)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	update.Reconciliation.NetworkAuthorityV2.CheckedAt = timestamppb.New(now)
	update.Reconciliation.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(2 * time.Second))
	if guard.Reconcile(ctx, update.Reconciliation, update.Features, update.CredentialExpiry) != nil {
		panic("initial fixture authority")
	}
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
		now := time.Now()
		update.Reconciliation.NetworkAuthorityV2.CheckedAt = timestamppb.New(now)
		update.Reconciliation.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(40 * time.Second))
		if guard.Reconcile(ctx, update.Reconciliation, update.Features, update.CredentialExpiry) != nil {
			cancel()
		}
	}()
	defer func() { cancel(); <-renewed; guard.Close() }()
	collectorConfig := evidence.Config{Secrets: []string{"synthetic-session-secret"}, MaxTotalBytes: 1 << 20}
	if os.Args[3] == "reject-events" {
		collectorConfig.MaxEventBytes = 8
	}
	collector, err := evidence.NewCollector(collectorConfig)
	if err != nil {
		panic(err)
	}
	defer collector.Close()
	started := make(chan struct{}, 1)
	sawStart := false
	collector.SetLiveSink(func(entry evidence.LiveEntry) {
		if strings.Contains(string(entry.Data), "ROOT_SERVICE_STARTED") {
			sawStart = true
			select {
			case started <- struct{}{}:
			default:
			}
		}
	})
	stopper := make(chan struct{})
	if os.Args[3] == "withdraw" {
		go func() {
			defer close(stopper)
			select {
			case <-ctx.Done():
			case <-started:
				_ = guard.Withdraw()
			}
		}()
	} else {
		close(stopper)
	}
	defer func() { cancel(); <-stopper }()
	released := false
	options := measuredclient.SessionOptions{Job: job, Request: request, Files: files, PreparationDeadline: time.Now().Add(job.EffectivePolicy.PreparationTimeout.AsDuration()), MaximumLogBytes: 1 << 20, BeforeRelease: func(context.Context) error {
		if released {
			return measuredclient.ErrSession
		}
		released = true
		if os.Args[3] == "reject-release" {
			return measuredclient.ErrSession
		}
		return nil
	}}
	var secretFiles *ts.Files
	var descriptors []ts.Descriptor
	defer func() {
		for _, descriptor := range descriptors {
			descriptor.File.Close()
		}
		if secretFiles != nil {
			secretFiles.Close()
		}
	}()
	if os.Args[3] == "secrets" || os.Args[3] == "secrets-expired" {
		options.PrepareSecrets = func(context.Context, *runtimeidentity.NetworkObservation) ([]ts.Descriptor, time.Time, error) {
			var err error
			secretFiles, err = ts.New([]ts.Input{{Name: "license", Value: []byte("synthetic-session-secret")}})
			if err != nil {
				return nil, time.Time{}, err
			}
			descriptors, err = secretFiles.ReadOnlyDescriptors()
			expires := time.Now().Add(20 * time.Second)
			if os.Args[3] == "secrets-expired" {
				expires = time.Now().Add(-time.Second)
			}
			return descriptors, expires, err
		}
	}
	result, err := measuredclient.Run(ctx, channel, guard, options, collector)
	if os.Args[3] == "reject-events" {
		var failure *measuredclient.SessionFailure
		if result != nil || !errors.Is(err, measuredclient.ErrSession) || !errors.As(err, &failure) || !failure.RetiredFor(job) || !released || !sawStart {
			panic("event refusal lost authenticated retirement or became success")
		}
		changed := proto.Clone(job).(*p.JobSpecification)
		changed.NormalizedConfigurationJson = []byte(`{"changed":true}`)
		if failure.RetiredFor(changed) || failure.RetiredFor(nil) {
			panic("failed retirement escaped exact execution binding")
		}
		return
	}
	if os.Args[3] != "complete" && os.Args[3] != "secrets" {
		if err == nil || result != nil || !released || sawStart != (os.Args[3] == "withdraw") {
			panic("refused session crossed its execution or completion boundary")
		}
		return
	}
	if err != nil || result == nil || !released || !sawStart || result.Observation() == nil {
		code, infrastructure, outcomeErr := result.Outcome()
		panic(fmt.Sprintf("session result/startup mismatch: sessionError=%v result=%t released=%t startup=%t observation=%t exit=%d infrastructure=%t outcomeError=%v", err, result != nil, released, sawStart, result.Observation() != nil, code, infrastructure, outcomeErr))
	}
	bundle, err := collector.Snapshot(ctx)
	if err != nil {
		panic(err)
	}
	defer bundle.CompleteLog.Archive.Close()
	if os.Args[3] == "secrets" && !strings.Contains(bundle.Stdout, "ROOT_SECRET_READ_ONLY_OK") {
		panic("late secret did not reach read-only guest mount")
	}
	exit, infra, err := result.Outcome()
	if err != nil || exit != 0 || infra || !strings.Contains(bundle.Stdout, "ROOT_SERVICE_OK") || strings.Contains(bundle.Stdout, "synthetic-session-secret") || !strings.Contains(bundle.Stdout, evidence.RedactionMarker) || len(bundle.Events) != 1 || string(bundle.Events[0].Payload) != "{\"syntheticRootService\":true}" {
		panic("root service result mismatch")
	}
	terminal, err := terminalevidence.NewContextV2(job)
	if err != nil {
		panic("fixture terminal context refused")
	}
	projected := execution.Result{TerminalContext: terminal, MeasuredNetwork: result.Observation()}
	proof, err := projected.FreezeTerminalEvidence("fixture-runner")
	if err != nil || terminalevidence.ValidateFrozenV2(proof, job, "fixture-runner") != nil {
		panic("opaque measured terminal bridge refused")
	}
	changed := proto.Clone(job).(*p.JobSpecification)
	changed.TargetPluginName = "DifferentFixture"
	changedContext, err := terminalevidence.NewContextV2(changed)
	if err != nil {
		panic("changed fixture context")
	}
	projected.TerminalContext = changedContext
	if substituted, err := projected.FreezeTerminalEvidence("fixture-runner"); err == nil || substituted != nil {
		panic("opaque observation accepted changed execution")
	}
}
