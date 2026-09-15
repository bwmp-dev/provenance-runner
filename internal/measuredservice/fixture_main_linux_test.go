//go:build linux

package measuredservice

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/measuredclient"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/provider/gvisor"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case gvisor.MeasuredNetworkChildCommand:
			os.Exit(gvisor.RunMeasuredNetworkChild(os.Args[2:], os.Stderr))
		case gvisor.RouterChildCommand:
			os.Exit(gvisor.RunRouterChild(os.Args[2:], os.Stderr))
		case "service-client":
			serviceFixtureClient()
			return
		}
		if strings.HasPrefix(os.Args[1], "-Xms") {
			// Synthetic Java stand-in only, inside the explicitly prepared
			// measured guest. It never interprets or executes any JAR bytes.
			if os.Getuid() != 65532 || os.Getgid() != 65532 {
				os.Exit(125)
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
	if len(os.Args) != 4 || (os.Args[3] != "complete" && os.Args[3] != "withdraw" && os.Args[3] != "reject-release") || os.Getuid() != 65532 || os.Getgid() != 65532 || os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" {
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
	collector, err := evidence.NewCollector(evidence.Config{Secrets: []string{"synthetic-session-secret"}, MaxTotalBytes: 1 << 20})
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
	result, err := measuredclient.Run(ctx, channel, guard, measuredclient.SessionOptions{Job: job, Request: request, Files: files, PreparationDeadline: time.Now().Add(job.EffectivePolicy.PreparationTimeout.AsDuration()), MaximumLogBytes: 1 << 20, BeforeRelease: func(context.Context) error {
		if released {
			return measuredclient.ErrSession
		}
		released = true
		if os.Args[3] == "reject-release" {
			return measuredclient.ErrSession
		}
		return nil
	}}, collector)
	if os.Args[3] != "complete" {
		if err == nil || result != nil || !released || sawStart != (os.Args[3] == "withdraw") {
			panic("refused session crossed its execution or completion boundary")
		}
		return
	}
	if err != nil || result == nil || !released || !sawStart || result.Observation() == nil {
		panic(fmt.Sprintf("session result/startup mismatch: %v", err))
	}
	bundle, err := collector.Snapshot(ctx)
	if err != nil {
		panic(err)
	}
	defer bundle.CompleteLog.Archive.Close()
	exit, infra, err := result.Outcome()
	if err != nil || exit != 0 || infra || !strings.Contains(bundle.Stdout, "ROOT_SERVICE_OK") || strings.Contains(bundle.Stdout, "synthetic-session-secret") || !strings.Contains(bundle.Stdout, evidence.RedactionMarker) || len(bundle.Events) != 1 || string(bundle.Events[0].Payload) != "{\"syntheticRootService\":true}" {
		panic("root service result mismatch")
	}
}
