//go:build linux

package controlchannel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func pair(t *testing.T, kind int) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, kind|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]*net.UnixConn, 0, 2)
	for _, fd := range fds {
		file := os.NewFile(uintptr(fd), "channel-fixture")
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn.(*net.UnixConn))
		t.Cleanup(func() { _ = conn.Close() })
	}
	return connections[0], connections[1]
}

func deadline() time.Time { return time.Now().Add(time.Second) }

func TestPeerAndSocketType(t *testing.T) {
	for _, kind := range []int{unix.SOCK_STREAM, unix.SOCK_SEQPACKET} {
		left, _ := pair(t, kind)
		if _, err := New(left, uint32(os.Getuid())+1); err == nil {
			t.Fatal("foreign peer accepted")
		}
		_, err := New(left, uint32(os.Getuid()))
		if (err == nil) != (kind == unix.SOCK_SEQPACKET) {
			t.Fatal("socket type not enforced")
		}
	}
	if _, err := New(nil, 0); err == nil {
		t.Fatal("nil socket")
	}
}

func TestRoundTripReadonlyDescriptorAndCloexec(t *testing.T) {
	left, right := pair(t, unix.SOCK_SEQPACKET)
	sender, _ := New(left, uint32(os.Getuid()))
	receiver, _ := New(right, uint32(os.Getuid()))
	path := t.TempDir() + "/artifact"
	if err := os.WriteFile(path, []byte("synthetic input"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := sender.Send(Packet{Kind: Start, Sequence: 1, Payload: []byte("bounded"), Files: []*os.File{file}}, deadline()); err != nil {
		t.Fatal(err)
	}
	packet, err := receiver.Receive(deadline())
	if err != nil {
		t.Fatal(err)
	}
	if packet.Kind != Start || packet.Sequence != 1 || string(packet.Payload) != "bounded" || len(packet.Files) != 1 {
		t.Fatal("packet changed")
	}
	defer packet.Files[0].Close()
	flags, err := unix.FcntlInt(packet.Files[0].Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("received descriptor inheritable")
	}
	content, err := io.ReadAll(packet.Files[0])
	if err != nil || string(content) != "synthetic input" {
		t.Fatal("descriptor changed")
	}
	if err := receiver.Send(Packet{Kind: Result, Sequence: 1}, deadline()); err != nil {
		t.Fatal(err)
	}
	if packet, err := sender.Receive(deadline()); err != nil || packet.Kind != Result {
		t.Fatal("reply failed", err)
	}
}

func TestMalformedAndTruncatedPacketsPermanentlyClose(t *testing.T) {
	for _, mutation := range []string{"magic", "version", "reserved", "kind", "sequence", "length", "files", "short", "oversized", "rights-overflow", "writable"} {
		t.Run(mutation, func(t *testing.T) {
			left, right := pair(t, unix.SOCK_SEQPACKET)
			receiver, _ := New(right, uint32(os.Getuid()))
			data := make([]byte, headerSize)
			copy(data, "PVC1")
			data[4], data[5] = 1, byte(Start)
			binary.BigEndian.PutUint64(data[8:16], 1)
			var rights []byte
			switch mutation {
			case "magic":
				data[0] = 'X'
			case "version":
				data[4] = 2
			case "reserved":
				data[23] = 1
			case "kind":
				data[5] = 99
			case "sequence":
				data[15] = 0
			case "length":
				data[19] = 1
			case "files":
				data[21] = 1
			case "short":
				data = data[:4]
			case "oversized":
				data = append(data, bytes.Repeat([]byte{'a'}, MaximumPayload+1)...)
			case "rights-overflow", "writable":
				file, err := os.CreateTemp(t.TempDir(), "input")
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				count := 1
				if mutation == "rights-overflow" {
					count = MaximumFiles + 1
				}
				fds := make([]int, count)
				for i := range fds {
					fds[i] = int(file.Fd())
				}
				rights = unix.UnixRights(fds...)
				binary.BigEndian.PutUint16(data[20:22], uint16(count))
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := left.WriteMsgUnix(data, rights, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := receiver.Receive(deadline()); err == nil {
				t.Fatal("malformed packet accepted")
			}
			if _, err := receiver.Receive(deadline()); err == nil {
				t.Fatal("failed channel resumed")
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(after) > len(before) {
				t.Fatal("descriptor leaked on refusal")
			}
		})
	}
}

func TestBoundedDeadlineAndSendRefusal(t *testing.T) {
	left, right := pair(t, unix.SOCK_SEQPACKET)
	sender, _ := New(left, uint32(os.Getuid()))
	receiver, _ := New(right, uint32(os.Getuid()))
	if err := sender.Send(Packet{Kind: Start, Sequence: 0}, deadline()); err == nil {
		t.Fatal("zero sequence accepted")
	}
	if _, err := receiver.Receive(time.Now().Add(20 * time.Millisecond)); err == nil {
		t.Fatal("EOF accepted")
	}
	left, right = pair(t, unix.SOCK_SEQPACKET)
	sender, _ = New(left, uint32(os.Getuid()))
	receiver, _ = New(right, uint32(os.Getuid()))
	if _, err := receiver.Receive(time.Now().Add(20 * time.Millisecond)); err == nil {
		t.Fatal("unbounded read")
	}
	if err := sender.Send(Packet{Kind: Start, Sequence: 1}, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("unbounded deadline")
	}
}

func TestConsecutiveSequencesAndMaximumPayload(t *testing.T) {
	left, right := pair(t, unix.SOCK_SEQPACKET)
	sender, _ := New(left, uint32(os.Getuid()))
	receiver, _ := New(right, uint32(os.Getuid()))
	for sequence := uint64(1); sequence <= 2; sequence++ {
		payload := bytes.Repeat([]byte{'x'}, MaximumPayload)
		if err := sender.Send(Packet{Kind: Reconcile, Sequence: sequence, Payload: payload}, deadline()); err != nil {
			t.Fatal(err)
		}
		packet, err := receiver.Receive(deadline())
		if err != nil || packet.Sequence != sequence || !bytes.Equal(payload, packet.Payload) {
			t.Fatal("maximum frame failed", err)
		}
	}
	if err := sender.Send(Packet{Kind: Reconcile, Sequence: 2}, deadline()); err == nil {
		t.Fatal("outgoing replay accepted")
	}
	left, right = pair(t, unix.SOCK_SEQPACKET)
	receiver, _ = New(right, uint32(os.Getuid()))
	data := make([]byte, headerSize)
	copy(data, "PVC1")
	data[4], data[5] = 1, byte(Start)
	binary.BigEndian.PutUint64(data[8:16], 2)
	if _, _, err := left.WriteMsgUnix(data, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Receive(deadline()); err == nil {
		t.Fatal("incoming sequence gap accepted")
	}
}
