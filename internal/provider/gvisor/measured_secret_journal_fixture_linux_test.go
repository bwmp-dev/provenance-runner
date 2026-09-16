//go:build linux

package gvisor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	"golang.org/x/sys/unix"
)

func measuredSecretJournalFixture(t *testing.T) {
	requireMeasuredBundleFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("/dev/shm", "measured-secret-journal-")
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(root, 0711) != nil {
		t.Fatal("parent mode")
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	defer func() {
		if !t.Failed() {
			if err := os.Remove(root); err != nil {
				t.Error(err)
			}
		}
	}()
	for _, mode := range []string{"normal", "cold", "foreign", "intent-only", "replaced", "wrong-boot", "wrong-parent"} {
		t.Run(mode, func(t *testing.T) {
			j, groups := openBundleSecretFixture(t, parent)
			if j.recover(ctx) != nil {
				t.Fatal("initial recovery")
			}
			if mode == "foreign" {
				path := filepath.Join(root, "foreign")
				if os.Mkdir(path, 0700) != nil {
					t.Fatal("foreign fixture")
				}
				if j.recover(ctx) == nil {
					t.Fatal("unknown child accepted")
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatal("unknown child removed")
				}
				if os.Remove(path) != nil || j.recover(ctx) != nil {
					t.Fatal("foreign fixture retirement")
				}
			} else {
				job := measuredSpecJob(t)
				b, err := j.create(job)
				if err != nil {
					t.Fatal(err)
				}
				if b.record.SecretBoot == "" || b.record.SecretIno == 0 {
					t.Fatal("secret ownership not recorded")
				}
				if mode == "intent-only" {
					if unix.Unlinkat(int(j.state.Fd()), b.record.Job+".owned.json", 0) != nil {
						t.Fatal("intent-only setup")
					}
				} else {
					owner, err := ts.New([]ts.Input{{Name: "license", Value: []byte("synthetic-journal-value")}})
					if err != nil {
						t.Fatal(err)
					}
					defer owner.Close()
					views, err := owner.ReadOnlyDescriptors()
					if err != nil {
						t.Fatal(err)
					}
					defer views[0].File.Close()
					dir, err := openBundleAt(j.secretParent, b.record.Job, unix.O_RDONLY|unix.O_DIRECTORY, 0)
					if err != nil {
						t.Fatal(err)
					}
					err = stageMeasuredSecrets(ctx, dir, views, np.MappedIdentity{UID: 40000, GID: 40000, OverflowUID: 40001, OverflowGID: 40001}, time.Now().Add(time.Minute))
					dir.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
				if mode == "replaced" {
					path := filepath.Join(root, b.record.Job)
					if os.Rename(path, path+"-retained") != nil || os.Mkdir(path, 0700) != nil {
						t.Fatal("replacement fixture")
					}
					if j.cleanup(ctx, b) == nil {
						t.Fatal("replacement removed")
					}
					if os.Remove(path) != nil || os.Rename(path+"-retained", path) != nil {
						t.Fatal("restore exact retained inode")
					}
				}
				if mode == "wrong-boot" || mode == "wrong-parent" {
					wrong := b.record
					if mode == "wrong-boot" {
						wrong.SecretBoot = "11111111-1111-1111-1111-111111111111"
					} else {
						wrong.SecretParentIno++
					}
					if j.removeSecretDirectory(ctx, wrong, true) == nil {
						t.Fatal("foreign ownership accepted")
					}
					if _, err := os.Stat(filepath.Join(root, b.record.Job, "license")); err != nil {
						t.Fatal("foreign ownership deleted secret")
					}
				}
				if mode == "cold" || mode == "intent-only" {
					// Model lost userspace owners after cgroup retirement. Persistent
					// records and tmpfs inodes remain; no authority is reconstructed.
					if groups.Cleanup(ctx, b.scope) != nil {
						t.Fatal("scope retirement")
					}
					if b.directory.Close() != nil {
						t.Fatal("old handle close")
					}
					delete(j.active, b.record.Job)
					if j.close() != nil || groups.Close() != nil {
						t.Fatal("old owners close")
					}
					j, groups = openBundleSecretFixture(t, parent)
					if j.recover(ctx) != nil {
						t.Fatal("cold secret recovery")
					}
				} else if j.cleanup(ctx, b) != nil {
					t.Fatal("secret cleanup")
				}
			}
			if j.close() != nil || groups.Close() != nil {
				t.Fatal("journal close")
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatal("owned secret directory remains")
			}
		})
	}
}
