//go:build linux

package controlchannel

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	"golang.org/x/sys/unix"
)

func secretChannels(t *testing.T) (*Channel, *Channel) {
	t.Helper()
	a, b := pair(t, unix.SOCK_SEQPACKET)
	s, err := New(a, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(b, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	until := deadline()
	if s.Send(Packet{Kind: Start, Sequence: 1}, until) != nil {
		t.Fatal("initial packet")
	}
	if _, err := r.Receive(until); err != nil {
		t.Fatal(err)
	}
	return s, r
}

func TestSecretDescriptorAssembly(t *testing.T) {
	for _, count := range []int{1, 16, 17, 64} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var inputs []ts.Input
			var names []string
			for i := 0; i < count; i++ {
				name := fmt.Sprintf("secret%02d", i)
				names = append(names, name)
				inputs = append(inputs, ts.Input{Name: name, Value: []byte("synthetic-wire-value")})
			}
			owner, err := ts.New(inputs)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			views, err := owner.ReadOnlyDescriptors()
			if err != nil {
				t.Fatal(err)
			}
			var files []*os.File
			for _, v := range views {
				files = append(files, v.File)
				defer v.File.Close()
			}
			s, r := secretChannels(t)
			defer s.Close()
			defer r.Close()
			until, expires := deadline(), time.Now().Add(30*time.Second)
			last, err := SendSecrets(s, names, files, expires, 1, until)
			if err != nil || last != uint64(2+(count+15)/16) {
				t.Fatal("send assembly", err)
			}
			first, err := r.Receive(until)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReceiveSecrets(r, first, names, expires, until)
			if err != nil {
				t.Fatal(err)
			}
			defer got.Close()
			if len(got.Files) != count || !got.ExpiresAt.Equal(expires) {
				t.Fatal("wrong assembly")
			}
			for _, f := range got.Files {
				value, err := ts.ReadSealedDescriptor(f)
				if err != nil || string(value) != "synthetic-wire-value" {
					t.Fatal("sealed descriptor lost")
				}
				clear(value)
			}
			raw, err := json.Marshal(got)
			if err != nil || string(raw) != "{}" || fmt.Sprintf("%#v", got) != "[received secret descriptors]" {
				t.Fatal("diagnostic serialization")
			}
			if s.Send(Packet{Kind: Release, Sequence: last + 1}, until) != nil {
				t.Fatal("following sequence")
			}
			if packet, err := r.Receive(until); err != nil || packet.Kind != Release {
				t.Fatal("following release")
			}
		})
	}
}

func TestSecretMetadataRefusals(t *testing.T) {
	for _, mode := range []string{"duplicate-key", "unknown-key", "wrong-name", "expired", "beyond-lease", "whitespace", "unsorted", "wrong-kind"} {
		t.Run(mode, func(t *testing.T) {
			s, r := secretChannels(t)
			defer s.Close()
			defer r.Close()
			expires := time.Now().Add(30 * time.Second)
			header := secretHeader{1, []string{"license"}, expires.UnixNano()}
			if mode == "expired" {
				header.ExpiresUnixNano = time.Now().Add(-time.Second).UnixNano()
			}
			if mode == "wrong-name" {
				header.Names = []string{"other"}
			}
			if mode == "unsorted" {
				header.Names = []string{"b", "a"}
			}
			raw, _ := json.Marshal(header)
			if mode == "duplicate-key" {
				raw = append([]byte(`{"version":1,`), raw[1:]...)
			}
			if mode == "unknown-key" {
				raw = append([]byte(`{"unknown":1,`), raw[1:]...)
			}
			if mode == "whitespace" {
				raw = append(raw, ' ')
			}
			if mode == "beyond-lease" {
				expires = expires.Add(-time.Second)
			}
			kind := SecretDelivery
			if mode == "wrong-kind" {
				kind = Release
			}
			until := deadline()
			if s.Send(Packet{Kind: kind, Sequence: 2, Payload: raw}, until) != nil {
				t.Fatal("fixture send")
			}
			first, err := r.Receive(until)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := ReceiveSecrets(r, first, []string{"license"}, expires, until); err == nil || got != nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}

func TestSecretAssemblyPartialFailureClosesDescriptors(t *testing.T) {
	owner, err := ts.New([]ts.Input{{Name: "license", Value: []byte("synthetic-partial")}})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	views, err := owner.ReadOnlyDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	defer views[0].File.Close()
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	before := count()
	for i := 0; i < 20; i++ {
		s, r := secretChannels(t)
		until, expires := deadline(), time.Now().Add(time.Minute)
		raw, _ := json.Marshal(secretHeader{1, []string{"license", "second"}, expires.UnixNano()})
		if s.Send(Packet{Kind: SecretDelivery, Sequence: 2, Payload: raw}, until) != nil || s.Send(Packet{Kind: SecretDelivery, Sequence: 3, Files: []*os.File{views[0].File}}, until) != nil {
			t.Fatal("partial fixture")
		}
		first, err := r.Receive(until)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := ReceiveSecrets(r, first, []string{"license", "second"}, expires, until); err == nil || got != nil {
			t.Fatal("short descriptor batch accepted")
		}
		s.Close()
		r.Close()
	}
	if count() != before {
		t.Fatal("received descriptors leaked")
	}
}

func TestSecretAssemblyDeadlineAndBorrowedOwnership(t *testing.T) {
	owner, err := ts.New([]ts.Input{{Name: "license", Value: []byte("synthetic-deadline")}})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	views, err := owner.ReadOnlyDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	defer views[0].File.Close()
	s, r := secretChannels(t)
	defer s.Close()
	defer r.Close()
	expires := time.Now().Add(time.Minute)
	if _, err := SendSecrets(s, []string{"license"}, []*os.File{views[0].File}, expires, 1, time.Now().Add(6*time.Second)); err == nil {
		t.Fatal("extended assembly deadline accepted")
	}
	if _, err := views[0].File.Stat(); err != nil {
		t.Fatal("borrowed file closed on refusal")
	}
	s, r = secretChannels(t)
	defer s.Close()
	defer r.Close()
	until := time.Now().Add(20 * time.Millisecond)
	raw, _ := json.Marshal(secretHeader{1, []string{"license"}, expires.UnixNano()})
	if s.Send(Packet{Kind: SecretDelivery, Sequence: 2, Payload: raw}, until) != nil {
		t.Fatal("timeout header")
	}
	first, err := r.Receive(until)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ReceiveSecrets(r, first, []string{"license"}, expires, until); err == nil || got != nil {
		t.Fatal("missing batch accepted")
	}
	if time.Until(until) > 0 {
		t.Fatal("assembly did not exercise deadline")
	}
	if got, err := ReceiveSecrets(nil, Packet{Files: []*os.File{views[0].File}}, nil, time.Time{}, time.Time{}); err == nil || got != nil {
		t.Fatal("nil channel accepted")
	}
	if _, err := views[0].File.Stat(); err == nil {
		t.Fatal("received file not closed on initial refusal")
	}
}
