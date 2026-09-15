//go:build linux

package testsecrets

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadOnlyDescriptors(t *testing.T) {
	f, err := New([]Input{{Name: "license", Value: []byte("synthetic-value")}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	views, err := f.ReadOnlyDescriptors()
	if err != nil || len(views) != 1 {
		t.Fatalf("descriptor creation: %v", err)
	}
	defer views[0].File.Close()
	if _, err := ReadSealedDescriptor(f.files[0].file); err == nil {
		t.Fatal("original writable description accepted")
	}
	read, err := ReadSealedDescriptor(views[0].File)
	if err != nil || string(read) != "synthetic-value" {
		t.Fatal("sealed read failed")
	}
	clear(read)
	if _, err := sealedDescriptorStat(views[0].File, true); err != nil {
		t.Fatal(err)
	}
	if _, err := views[0].File.Write([]byte("x")); err == nil {
		t.Fatal("writable descriptor")
	}
	encoded, err := json.Marshal(views[0])
	if err != nil || string(encoded) != "{}" || fmt.Sprintf("%#v", views[0]) != "[test-secret descriptor]" {
		t.Fatal("descriptor exposed in diagnostics")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	value, err := io.ReadAll(views[0].File)
	defer clear(value)
	if err != nil || string(value) != "synthetic-value" {
		t.Fatal("view lifetime not independent")
	}
	if _, err := f.ReadOnlyDescriptors(); err == nil {
		t.Fatal("closed owner accepted")
	}
}

func TestReadSealedDescriptorRejectsInvalidUTF8(t *testing.T) {
	file, err := sealed([]byte{0xff})
	if err != nil {
		t.Fatal(err)
	}
	f := &Files{files: []memoryFile{{name: "fixture", file: file}}}
	defer f.Close()
	views, err := f.ReadOnlyDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	defer views[0].File.Close()
	if value, err := ReadSealedDescriptor(views[0].File); err == nil || value != nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestReadOnlyDescriptorRefusals(t *testing.T) {
	for _, f := range []*Files{nil, {}} {
		if _, err := f.ReadOnlyDescriptors(); err == nil {
			t.Fatal("empty owner accepted")
		}
	}
	persistent, err := os.CreateTemp(t.TempDir(), "not-memory")
	if err != nil {
		t.Fatal(err)
	}
	defer persistent.Close()
	if _, err := persistent.Write([]byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if err := persistent.Chmod(0444); err != nil {
		t.Fatal(err)
	}
	if _, err := sealedDescriptorStat(persistent, false); err == nil {
		t.Fatal("persistent file accepted")
	}
	fd, err := unix.MemfdCreate("unsealed-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	unsealed := os.NewFile(uintptr(fd), "unsealed-fixture")
	defer unsealed.Close()
	if _, err := unsealed.Write([]byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if err := unsealed.Chmod(0444); err != nil {
		t.Fatal(err)
	}
	if _, err := sealedDescriptorStat(unsealed, false); err == nil {
		t.Fatal("unsealed memory accepted")
	}
	if _, err := sealedDescriptorStat(nil, true); err == nil {
		t.Fatal("nil descriptor accepted")
	}
}

func TestReadOnlyDescriptorPartialFailureClosesViews(t *testing.T) {
	f, err := New([]Input{{Name: "a", Value: []byte("first")}, {Name: "b", Value: []byte("second")}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.files[1].file.Close(); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	before := count()
	for i := 0; i < 20; i++ {
		if views, err := f.ReadOnlyDescriptors(); err == nil || views != nil {
			t.Fatal("partial handoff returned")
		}
	}
	if count() != before {
		t.Fatal("partial handoff leaked descriptors")
	}
}
