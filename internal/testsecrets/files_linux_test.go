//go:build linux

package testsecrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAnonymousSealedFiles(t *testing.T) {
	value := []byte("private-memory-fixture\x00")
	input := Input{Name: "api.token", Value: value}
	files, err := New([]Input{input})
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	mounts, err := files.Mounts()
	if err != nil || len(mounts) != 1 || mounts[0].Destination != Destination+"/api.token" {
		t.Fatal("mount metadata incorrect")
	}
	got, err := os.ReadFile(mounts[0].Source)
	if err != nil || !bytes.Equal(got, value) {
		t.Fatal("memory value changed")
	}
	clear(got)
	fd := files.files[0].file.Fd()
	if flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("descriptor inherited across exec")
	}
	if _, err := files.files[0].file.WriteAt([]byte("x"), 0); err == nil {
		t.Fatal("sealed file writable")
	}
	if err := files.files[0].file.Truncate(0); err == nil {
		t.Fatal("sealed file truncatable")
	}
	reopened, err := os.OpenFile(mounts[0].Source, os.O_RDWR, 0)
	if err == nil {
		if _, err := reopened.WriteAt([]byte("x"), 0); err == nil {
			t.Fatal("reopened inode writable")
		}
		reopened.Close()
	}
	for _, object := range []any{input, files} {
		encoded, _ := json.Marshal(object)
		if strings.Contains(fmt.Sprintf("%v %+v %#v %s", object, object, object, encoded), "private-memory-fixture") {
			t.Fatal("diagnostics disclosed value")
		}
	}
	if err := files.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := files.Mounts(); err == nil {
		t.Fatal("closed file set supplied mounts")
	}
	if _, err := os.Open(mounts[0].Source); err == nil {
		t.Fatal("closed descriptor remained accessible")
	}
	if err := files.Close(); err != nil {
		t.Fatal("second close failed")
	}
}

func TestMemoryFileBounds(t *testing.T) {
	cases := [][]Input{
		nil, {{Name: "token", Value: nil}}, {{Name: "../token", Value: []byte("x")}},
		{{Name: "TOKEN", Value: []byte("x")}}, {{Name: "a..b", Value: []byte("x")}},
		{{Name: strings.Repeat("a", 64), Value: []byte("x")}},
		{{Name: "a", Value: []byte{0xff}}}, {{Name: "a", Value: make([]byte, 65537)}},
		{{Name: "a", Value: make([]byte, 65536)}, {Name: "b", Value: []byte("x")}},
		{{Name: "a", Value: []byte("x")}, {Name: "a", Value: []byte("y")}},
		{{Name: "b", Value: []byte("x")}, {Name: "a", Value: []byte("y")}},
	}
	for _, inputs := range cases {
		if files, err := New(inputs); err == nil {
			files.Close()
			t.Fatal("invalid set accepted")
		}
	}
	files, err := New([]Input{{Name: "token", Value: make([]byte, 65536)}})
	if err != nil {
		t.Fatal("maximum input refused")
	}
	files.Close()
	inputs := make([]Input, 65)
	for i := range inputs {
		inputs[i] = Input{Name: fmt.Sprintf("token-%02d", i), Value: []byte("x")}
	}
	if files, err := New(inputs); err == nil {
		files.Close()
		t.Fatal("65 inputs accepted")
	}
	files, err = New(inputs[:64])
	if err != nil {
		t.Fatal("64 inputs refused")
	}
	files.Close()
}
