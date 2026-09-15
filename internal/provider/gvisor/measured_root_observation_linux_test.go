//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func measuredRootObservationFixture(t *testing.T, job *p.JobSpecification, observation *runtimeidentity.NetworkObservation) {
	measuredRootTransferFixture(t, job, observation, nil, nil)
}

func measuredRootTransferFixture(t *testing.T, job *p.JobSpecification, observation *runtimeidentity.NetworkObservation, result, completion []byte) {
	t.Helper()
	if os.Getuid() != 0 || os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" {
		t.Fatal("disposable root observation required")
	}
	raw, err := runtimeidentity.EncodeRootObservation(job, observation)
	if err != nil {
		t.Fatal("sealed root export", err)
	}
	root, err := os.MkdirTemp("/tmp", "measured-observation-client-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(root); err != nil {
			t.Error("observation directory retirement", err)
		}
	})
	if os.Chmod(root, 0711) != nil {
		t.Fatal("observation directory")
	}
	source, err := os.Open("/state-input/guest")
	if err != nil {
		t.Fatal(err)
	}
	binary, err := io.ReadAll(io.LimitReader(source, (16<<20)+1))
	source.Close()
	if err != nil || len(binary) > 16<<20 {
		t.Fatal("bounded observation client")
	}
	clientPath := filepath.Join(root, "client")
	client, err := os.OpenFile(clientPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0555)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := client.Write(binary)
	closeErr := client.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("observation client copy")
	}
	defer os.Remove(clientPath)
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	listener, err := controlchannel.OpenRootListener(parent, 65532, 65532)
	if listener != nil {
		defer listener.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	jobBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	modes := []string{"valid", "malformed", "wrong-kind"}
	if completion != nil {
		modes = []string{"result"}
	}
	for _, mode := range modes {
		file, err := os.CreateTemp(root, "job-")
		if err != nil {
			t.Fatal(err)
		}
		path := file.Name()
		if _, err := file.Write(jobBytes); err != nil {
			file.Close()
			t.Fatal(err)
		}
		file.Close()
		input, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if os.Remove(path) != nil {
			input.Close()
			t.Fatal("unlink fixture job")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		command := exec.CommandContext(ctx, clientPath, "control-observation", filepath.Join(root, controlchannel.SocketName), mode)
		command.Env = []string{"PATH=/usr/bin:/bin", "PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1"}
		command.ExtraFiles = []*os.File{input}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL}
		var diagnostics bytes.Buffer
		command.Stderr = &diagnostics
		done := make(chan error, 1)
		go func() { runtime.LockOSThread(); defer runtime.UnlockOSThread(); done <- command.Run() }()
		peer, err := listener.Accept(time.Now().Add(5 * time.Second))
		if err != nil {
			cancel()
			childErr := <-done
			input.Close()
			t.Fatal("root observation peer", err, childErr, diagnostics.String())
		}
		kind, payload := controlchannel.Observation, append([]byte(nil), raw...)
		if mode == "malformed" {
			payload = append(payload, 0)
		}
		if mode == "wrong-kind" {
			kind = controlchannel.Result
		}
		sendErr := peer.Send(controlchannel.Packet{Kind: kind, Sequence: 1, Payload: payload}, time.Now().Add(3*time.Second))
		if sendErr == nil && mode == "result" {
			sequence := uint64(2)
			for offset := 0; offset < len(result) && sendErr == nil; {
				end := min(offset+controlchannel.MaximumPayload, len(result))
				sendErr = peer.Send(controlchannel.Packet{Kind: controlchannel.Result, Sequence: sequence, Payload: result[offset:end]}, time.Now().Add(3*time.Second))
				sequence++
				offset = end
			}
			if sendErr == nil {
				sendErr = peer.Send(controlchannel.Packet{Kind: controlchannel.Completion, Sequence: sequence, Payload: completion}, time.Now().Add(3*time.Second))
			}
		}
		peer.Close()
		childErr := <-done
		cancel()
		input.Close()
		if sendErr != nil || childErr != nil {
			t.Fatal("root observation transfer", mode, sendErr, childErr, diagnostics.String())
		}
	}
	if listener.Close() != nil {
		t.Fatal("observation listener retirement")
	}
}
