//go:build linux

package controlchannel

import (
	"bytes"
	"encoding/binary"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func startChannels(t *testing.T) (*Channel, *Channel) {
	t.Helper()
	left, right := pair(t, unix.SOCK_SEQPACKET)
	sender, err := New(left, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := New(right, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Close(); _ = receiver.Close() })
	return sender, receiver
}
func startFile(t *testing.T) *os.File {
	t.Helper()
	path := t.TempDir() + "/input"
	if err := os.WriteFile(path, []byte("synthetic descriptor"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}
func startHeader(length, count int) []byte {
	raw := make([]byte, 12)
	copy(raw, "PVS1")
	binary.BigEndian.PutUint32(raw[4:8], uint32(length))
	binary.BigEndian.PutUint16(raw[8:10], uint16(count))
	return raw
}

func TestStartAssemblyFullBoundsAndFollowingSequence(t *testing.T) {
	for _, size := range []int{1, MaximumPayload + 1, MaximumStartBytes} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			sender, receiver := startChannels(t)
			file := startFile(t)
			files := make([]*os.File, MaximumStartFiles)
			for i := range files {
				files[i] = file
			}
			payload := bytes.Repeat([]byte{71}, size)
			done := make(chan error, 1)
			until := time.Now().Add(5 * time.Second)
			go func() {
				last, err := SendStart(sender, payload, files, until)
				if err == nil {
					err = sender.Send(Packet{Kind: Release, Sequence: last + 1}, until)
				}
				done <- err
			}()
			request, err := ReceiveStart(receiver, until)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, f := range request.Files {
					_ = f.Close()
				}
			}()
			if !bytes.Equal(payload, request.Payload) || len(request.Files) != MaximumStartFiles {
				t.Fatal("start truncated")
			}
			packet, err := receiver.Receive(until)
			if err != nil || packet.Kind != Release || packet.Sequence != request.LastSequence+1 {
				t.Fatal("following sequence lost", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			for _, f := range request.Files {
				var raw [20]byte
				n, err := f.ReadAt(raw[:], 0)
				if err != nil && n == 0 {
					t.Fatal(err)
				}
				if string(raw[:n]) != "synthetic descriptor" {
					t.Fatal("file batch changed")
				}
			}
		})
	}
}

func TestStartAssemblyMalformedOrPartialClosesReceivedDescriptors(t *testing.T) {
	file := startFile(t)
	cases := map[string][]Packet{
		"bad header":     {{Kind: Start, Payload: []byte("bad"), Files: []*os.File{file}}},
		"header files":   {{Kind: Start, Payload: startHeader(1, 1), Files: []*os.File{file}}},
		"too large":      {{Kind: Start, Payload: startHeader(MaximumStartBytes+1, 1)}},
		"too many files": {{Kind: Start, Payload: startHeader(1, MaximumStartFiles+1)}},
		"short chunk":    {{Kind: Start, Payload: startHeader(2, 1)}, {Kind: Start, Payload: []byte{1}}},
		"chunk files":    {{Kind: Start, Payload: startHeader(1, 1)}, {Kind: Start, Payload: []byte{1}, Files: []*os.File{file}}},
		"wrong kind":     {{Kind: Start, Payload: startHeader(1, 1)}, {Kind: Cancel, Files: []*os.File{file}}},
		"file payload":   {{Kind: Start, Payload: startHeader(1, 1)}, {Kind: Start, Payload: []byte{1}}, {Kind: Start, Payload: []byte{1}, Files: []*os.File{file}}},
		"excess files":   {{Kind: Start, Payload: startHeader(1, 1)}, {Kind: Start, Payload: []byte{1}}, {Kind: Start, Files: []*os.File{file, file}}},
		"partial files":  {{Kind: Start, Payload: startHeader(1, 17)}, {Kind: Start, Payload: []byte{1}}, {Kind: Start, Files: []*os.File{file}}},
	}
	for name, packets := range cases {
		t.Run(name, func(t *testing.T) {
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			sender, receiver := startChannels(t)
			done := make(chan struct{})
			until := time.Now().Add(time.Second)
			go func() {
				defer close(done)
				defer sender.Close()
				for i, p := range packets {
					p.Sequence = uint64(i + 1)
					if sender.Send(p, until) != nil {
						return
					}
				}
			}()
			got, err := ReceiveStart(receiver, until)
			if err == nil || got != nil {
				t.Fatal("invalid assembly admitted")
			}
			<-done
			_ = receiver.Close()
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != len(before) {
				t.Fatal("received descriptors leaked")
			}
			if _, err := receiver.Receive(until); err == nil {
				t.Fatal("failed assembly resumed")
			}
		})
	}
}

func TestStartAssemblyUsesOneDeadline(t *testing.T) {
	sender, receiver := startChannels(t)
	until := time.Now().Add(30 * time.Millisecond)
	if err := sender.Send(Packet{Kind: Start, Sequence: 1, Payload: startHeader(1, 1)}, until); err != nil {
		t.Fatal(err)
	}
	if got, err := ReceiveStart(receiver, until); got != nil || err == nil {
		t.Fatal("incomplete request survived deadline")
	}
}
