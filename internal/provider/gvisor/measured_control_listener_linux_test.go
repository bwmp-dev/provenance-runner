//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/controlchannel"
)

func TestMeasuredControlListener(t *testing.T) {
	if os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" {
		t.Skip("explicit disposable listener fixture required")
	}
	if os.Getuid() != 0 || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		t.Fatal("disposable root listener required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container required")
	}
	if syscall.Setgroups([]int{}) != nil {
		t.Fatal("fixture supplementary groups")
	}
	root, err := os.MkdirTemp("/tmp", "measured-control-listener-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(root); err != nil {
			t.Error("owned listener directory not retired", err)
		}
	})
	if os.Chmod(root, 0711) != nil {
		t.Fatal("fixture directory mode")
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	l, err := controlchannel.OpenRootListener(parent, 65532, 65532)
	if l != nil {
		defer l.Close()
	}
	if err != nil {
		t.Fatal("root listener", err)
	}
	path := filepath.Join(root, controlchannel.SocketName)
	before, err := os.Lstat(path)
	if err != nil || before.Mode().Perm() != 0660 {
		t.Fatal("socket protection")
	}
	if other, err := controlchannel.OpenRootListener(parent, 65532, 65532); other != nil || err == nil {
		t.Fatal("existing socket replaced")
	}
	current, _ := os.Lstat(path)
	if !os.SameFile(before, current) {
		t.Fatal("existing socket changed")
	}
	wrong, err := net.DialTimeout("unixpacket", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if peer, err := l.Accept(time.Now().Add(time.Second)); peer != nil || err == nil {
		t.Fatal("wrong root peer admitted")
	}
	wrong.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The persistent fixture staging directory deliberately remains 0700. Copy
	// only the trusted client into this owned traversable directory; do not widen
	// access to the durable journals or other source fixtures for the worker UID.
	source, err := os.Open("/state-input/guest")
	if err != nil {
		t.Fatal(err)
	}
	binary, readErr := io.ReadAll(io.LimitReader(source, (16<<20)+1))
	source.Close()
	if readErr != nil || len(binary) == 0 || len(binary) > 16<<20 {
		t.Fatal("bounded fixture client")
	}
	clientPath := filepath.Join(root, "client")
	client, err := os.OpenFile(clientPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0555)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := client.Write(binary)
	closeErr := client.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("fixture client copy")
	}
	defer os.Remove(clientPath)
	command := exec.CommandContext(ctx, clientPath, "control-client", path)
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	command.Env = []string{"PATH=/usr/bin:/bin", "PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL}
	done := make(chan error, 1)
	go func() { runtime.LockOSThread(); defer runtime.UnlockOSThread(); done <- command.Run() }()
	peer, err := l.Accept(time.Now().Add(5 * time.Second))
	if err != nil {
		cancel()
		clientErr := <-done
		t.Fatal("worker peer authentication", err, clientErr, diagnostics.String())
	}
	packet, err := peer.Receive(time.Now().Add(time.Second))
	if err != nil || packet.Kind != controlchannel.Cancel || string(packet.Payload) != "synthetic peer" {
		cancel()
		peer.Close()
		<-done
		t.Fatal("worker request", err)
	}
	if err := peer.Send(controlchannel.Packet{Kind: controlchannel.Result, Sequence: 1, Payload: []byte("accepted")}, time.Now().Add(time.Second)); err != nil {
		cancel()
		peer.Close()
		<-done
		t.Fatal(err)
	}
	peer.Close()
	if err := <-done; err != nil {
		t.Fatal("worker did not authenticate root", err)
	}
	// Rename our exact socket, replace its entry with an owned inert fixture,
	// and prove Close preserves the replacement until original identity returns.
	if os.Rename(path, path+".owned") != nil {
		t.Fatal("fixture socket rename")
	}
	if os.WriteFile(path, []byte("synthetic foreign entry"), 0600) != nil {
		t.Fatal("fixture replacement")
	}
	if l.Close() == nil {
		t.Fatal("foreign socket entry removed")
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "synthetic foreign entry" {
		t.Fatal("foreign entry modified")
	}
	if os.Remove(path) != nil || os.Rename(path+".owned", path) != nil {
		t.Fatal("fixture identity restore")
	}
	if l.Close() != nil || l.Close() != nil {
		t.Fatal("original socket retirement")
	}
	l2, err := controlchannel.OpenRootListener(parent, 65532, 65532)
	if l2 != nil {
		defer l2.Close()
	}
	if err != nil {
		t.Fatal("fresh listener", err)
	}
	if os.Chmod(path, 0640) != nil {
		t.Fatal("fixture drift")
	}
	if peer, err := l2.Accept(time.Now().Add(time.Second)); peer != nil || err == nil {
		t.Fatal("socket drift admitted")
	}
	if os.Chmod(path, 0660) != nil {
		t.Fatal("fixture mode restore")
	}
	if peer, err := l2.Accept(time.Now().Add(time.Second)); peer != nil || err == nil {
		t.Fatal("drifted listener resumed")
	}
	if l2.Close() != nil {
		t.Fatal("drifted listener retirement")
	}
}
