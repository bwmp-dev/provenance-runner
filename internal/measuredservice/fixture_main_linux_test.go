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
	"github.com/bwmp-dev/provenance-runner/internal/guestoutput"
	"github.com/bwmp-dev/provenance-runner/internal/provider/gvisor"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
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
			fmt.Println("ROOT_SERVICE_OK")
			return
		}
	}
	os.Exit(m.Run())
}

func serviceFixtureClient() {
	if len(os.Args) != 3 || os.Getuid() != 65532 || os.Getgid() != 65532 || os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" {
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
	last, err := cc.SendStart(channel, request, files, time.Now().Add(10*time.Second))
	if err != nil {
		panic(err)
	}
	if channel.Send(cc.Packet{Kind: cc.Reconcile, Sequence: last + 1, Payload: ack}, time.Now().Add(3*time.Second)) != nil {
		panic("fixture acknowledgement")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	packet, err := channel.AwaitRootObservation(ctx)
	if err != nil {
		panic(err)
	}
	if _, err := runtimeidentity.ImportRootObservation(job, packet); err != nil {
		panic(err)
	}
	stream, err := cc.NewResultStream(ctx, channel)
	if err != nil {
		panic(err)
	}
	defer stream.Close()
	var output strings.Builder
	transcript, err := guestoutput.ReadStream(ctx, stream, 1<<20, func(_ guestoutput.Kind, raw []byte) error { _, err := output.Write(raw); return err })
	if err != nil {
		panic(err)
	}
	receipt, err := stream.Receipt()
	if err != nil {
		panic(err)
	}
	exit, infra, err := receipt.Outcome()
	claimed, claimedInfra := transcript.ClaimedExit()
	if err != nil || exit != 0 || infra || claimed != 0 || claimedInfra || !strings.Contains(output.String(), "ROOT_SERVICE_OK") || string(transcript.EventBytes()) != "{\"syntheticRootService\":true}\n" {
		panic("root service result mismatch")
	}
}
