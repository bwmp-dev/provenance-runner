//go:build linux

package measuredservice

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"golang.org/x/sys/unix"
)

func testChannels(t *testing.T) (*cc.Channel, *cc.Channel) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	channels := make([]*cc.Channel, 2)
	for i, fd := range fds {
		file := os.NewFile(uintptr(fd), "service fixture")
		connection, err := net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		channels[i], err = cc.New(connection.(*net.UnixConn), uint32(os.Getuid()))
		if err != nil {
			connection.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { channels[i].Close() })
	}
	return channels[0], channels[1]
}

func TestSenderSeparatesRootPhasesFromGuestBytes(t *testing.T) {
	a, b := testChannels(t)
	s := &sender{channel: a}
	if s.result([]byte("premature")) == nil {
		t.Fatal("guest output before observation")
	}
	if s.progress() != nil || s.observation([]byte("synthetic observation")) != nil || s.result([]byte("guest-controlled")) != nil || s.progress() != nil || s.completion([]byte("synthetic completion")) != nil {
		t.Fatal("sequencing")
	}
	for i, kind := range []cc.Kind{cc.Preparing, cc.Observation, cc.Result, cc.Result, cc.Completion} {
		packet, err := b.Receive(time.Now().Add(time.Second))
		if err != nil || packet.Kind != kind || packet.Sequence != uint64(i+1) || len(packet.Files) != 0 {
			t.Fatal("wrong phase", i, err)
		}
	}
	if s.result(nil) == nil || s.observation(nil) == nil || s.progress() == nil || s.completion(nil) == nil {
		t.Fatal("completed sender resumed")
	}
}

func TestServiceRefusesUnprovisionedAndInvalidRequestWithoutExecution(t *testing.T) {
	if server, err := New(context.Background(), Config{}); err == nil || server != nil {
		t.Fatal("unprovisioned root service")
	}
	a, b := testChannels(t)
	// Private construction exercises admission only; it is not kernel/root
	// acceptance. No controller is present and no artifact is executed.
	s := &Server{ctx: context.Background(), worker: uint32(os.Getuid()), source: &paper.RuntimeSource{}, maximum: 1 << 20}
	path := filepath.Join(t.TempDir(), "input")
	if os.WriteFile(path, []byte("synthetic input"), 0600) != nil {
		t.Fatal("fixture input")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), a) }()
	if _, err := cc.SendStart(b, []byte("invalid signed request"), []*os.File{file}, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("invalid request admitted")
		}
	case <-time.After(time.Second):
		t.Fatal("admission did not terminate")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("borrowed sender descriptor closed")
	}
	if _, err := b.Receive(time.Now().Add(time.Second)); err == nil {
		t.Fatal("failed request connection remained open")
	}
}

func TestServiceBusyAdmissionDoesNotWaitOrRead(t *testing.T) {
	a, _ := testChannels(t)
	s := &Server{ctx: context.Background()}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Serve(context.Background(), a); err == nil {
		t.Fatal("busy admission")
	}
}

func TestServiceRejectsTamperedSignedRequestBeforeController(t *testing.T) {
	source, manifest, job := serviceFixtureJob(t, []byte("synthetic java"), []byte("synthetic prepared"))
	// Preserve valid JSON and envelope encoding; only authentication is wrong.
	manifest.Signature[0] ^= 1
	raw, err := paper.EncodeMeasuredRequest(job, manifest)
	if err != nil {
		t.Fatal(err)
	}
	a, b := testChannels(t)
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("synthetic input"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// Admission-only test: deliberately no controller or measurement exists.
	// A tampered signature must be refused before either can be accessed.
	s := &Server{ctx: context.Background(), worker: uint32(os.Getuid()), source: source, maximum: 64 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, a) }()
	if _, err := cc.SendStart(b, raw, []*os.File{file}, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("tampered manifest admitted")
		}
	case <-ctx.Done():
		t.Fatal("tampered request did not terminate")
	}
	if _, err := b.Receive(time.Now().Add(time.Second)); err == nil {
		t.Fatal("tampered request produced a receipt")
	}
}
