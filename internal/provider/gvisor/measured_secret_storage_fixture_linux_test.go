//go:build linux

package gvisor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	"golang.org/x/sys/unix"
)

func measuredSecretStorageFixture(t *testing.T) {
	requireMeasuredBundleFixture(t)
	base, err := os.MkdirTemp("/dev/shm", "measured-secret-storage-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0711); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if !t.Failed() {
			if err := os.Remove(base); err != nil {
				t.Error(err)
			}
		}
	}()
	owner, err := ts.New([]ts.Input{{Name: "license", Value: []byte("synthetic-tmpfs-value")}})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	views, err := owner.ReadOnlyDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	defer views[0].File.Close()
	mapping := np.MappedIdentity{UID: 40000, GID: 40000, OverflowUID: 40001, OverflowGID: 40001}
	for _, mode := range []string{"success", "expired", "cancelled", "bad-name", "duplicate", "oversize", "persistent"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(base, mode)
			if mode == "persistent" {
				path = filepath.Join("/tmp/bundle-input", "secret-storage-refusal")
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			directory, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			defer func() {
				if t.Failed() {
					return
				}
				if mode == "success" {
					if err := os.Remove(filepath.Join(path, "license")); err != nil {
						t.Error(err)
					}
				}
				if err := os.Remove(path); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			expires := time.Now().Add(time.Minute)
			input := append([]ts.Descriptor(nil), views...)
			switch mode {
			case "expired":
				expires = time.Now().Add(-time.Second)
			case "cancelled":
				cancel()
			case "bad-name":
				input[0].Name = "../escape"
			case "duplicate":
				input = append(input, input[0])
			case "oversize":
				large, err := ts.New([]ts.Input{{Name: "a", Value: make([]byte, ts.MaximumBytes)}})
				if err != nil {
					t.Fatal(err)
				}
				defer large.Close()
				more, err := large.ReadOnlyDescriptors()
				if err != nil {
					t.Fatal(err)
				}
				defer more[0].File.Close()
				input = append(more, input...)
			}
			err = stageMeasuredSecrets(ctx, directory, input, mapping, expires)
			if mode != "success" {
				if err == nil {
					t.Fatal("unsafe storage accepted")
				}
				entries, err := os.ReadDir(path)
				if err != nil || len(entries) != 0 {
					t.Fatal("refusal materialized files")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var st unix.Stat_t
			if unix.Fstat(int(directory.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0550 || st.Uid != 0 || st.Gid != mapping.GID {
				t.Fatal("unsafe materialized directory")
			}
			if unix.Stat(filepath.Join(path, "license"), &st) != nil || st.Mode != unix.S_IFREG|0444 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 {
				t.Fatal("unsafe materialized file")
			}
			cmd := exec.Command("/bin/cat", filepath.Join(path, "license"))
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: mapping.UID, Gid: mapping.GID, Groups: []uint32{}}}
			raw, err := cmd.Output()
			defer clear(raw)
			if err != nil || string(raw) != "synthetic-tmpfs-value" {
				t.Fatal("mapped reader cannot access exact secret")
			}
			for _, args := range [][]string{{"/bin/chmod", "0700", path}, {"/bin/touch", filepath.Join(path, "replacement")}} {
				denied := exec.Command(args[0], args[1:]...)
				denied.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: mapping.UID, Gid: mapping.GID, Groups: []uint32{}}}
				if denied.Run() == nil {
					t.Fatal("mapped runtime changed protected secret directory")
				}
			}
			if stageMeasuredSecrets(ctx, directory, input, mapping, expires) == nil {
				t.Fatal("materialization repeated")
			}
		})
	}
}
