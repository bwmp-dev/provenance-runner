//go:build linux

package main

import (
	"context"
	"encoding/json"
	"github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/guestoutput"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"io"
	"net"
	"os"
	"time"
)

func init() {
	measuredObservationClient = func() bool {
		if len(os.Args) == 4 && os.Args[1] == "control-observation" {
			controlObservationFixture(os.Args[2], os.Args[3])
			return true
		}
		return false
	}
}

func controlObservationFixture(path, mode string) {
	if os.Getuid() != 65532 || os.Getgid() != 65532 || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" || (mode != "valid" && mode != "malformed" && mode != "wrong-kind" && mode != "result") {
		panic("disposable observation client required")
	}
	file := os.NewFile(3, "synthetic observation job")
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	file.Close()
	job := new(p.JobSpecification)
	if err != nil || len(raw) > 1<<20 || proto.Unmarshal(raw, job) != nil {
		panic("fixture job")
	}
	conn, err := net.DialTimeout("unixpacket", path, 3*time.Second)
	if err != nil {
		panic(err)
	}
	channel, err := controlchannel.New(conn.(*net.UnixConn), 0)
	if err != nil {
		conn.Close()
		panic(err)
	}
	defer channel.Close()
	packet, err := channel.ReceiveRootObservation(time.Now().Add(3 * time.Second))
	if mode == "wrong-kind" {
		if err == nil || packet != nil {
			panic("guest result kind became observation")
		}
		return
	}
	if err != nil {
		panic(err)
	}
	observed, err := runtimeidentity.ImportRootObservation(job, packet)
	if mode == "malformed" {
		if err == nil || observed != nil {
			panic("malformed observation admitted")
		}
		return
	}
	if err != nil {
		panic(err)
	}
	snapshot, err := observed.SnapshotFor(job.Lease, job.Attempt, job.Hashes)
	if err != nil || snapshot.Valid() || (snapshot.NetworkMode != "allowlist" && snapshot.NetworkMode != "restricted") {
		panic("root observation binding")
	}
	changed := proto.Clone(job).(*p.JobSpecification)
	changed.TargetPluginName += "changed"
	if imported, err := runtimeidentity.ImportRootObservation(changed, packet); imported != nil || err == nil {
		panic("foreign full job admitted")
	}
	var fake controlchannel.RootObservationPacket
	encoded, _ := json.Marshal(packet)
	if json.Unmarshal(encoded, &fake) != nil {
		panic("fixture receipt JSON")
	}
	if imported, err := runtimeidentity.ImportRootObservation(job, &fake); imported != nil || err == nil {
		panic("serialized receipt recreated proof")
	}
	payload, _ := packet.Payload()
	payload[0] ^= 1
	if _, err := runtimeidentity.ImportRootObservation(job, packet); err != nil {
		panic("mutable receipt escaped")
	}
	if mode == "result" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := controlchannel.NewResultStream(ctx, channel)
		if err != nil {
			panic(err)
		}
		defer stream.Close()
		transcript, err := guestoutput.ReadStream(ctx, stream, 1<<20, func(guestoutput.Kind, []byte) error { return nil })
		if err != nil {
			panic(err)
		}
		receipt, err := stream.Receipt()
		if err != nil {
			panic(err)
		}
		exit, infra, err := receipt.Outcome()
		claimedExit, claimedInfra := transcript.ClaimedExit()
		if err != nil || exit != claimedExit || infra != claimedInfra {
			panic("root and guest outcome mismatch")
		}
	}
}
