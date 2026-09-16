//go:build linux

package gvisor

import (
	"context"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

func requireMeasuredBundleFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" {
		t.Skip("explicit disposable measured fixture required")
	}
	if os.Getuid() != 0 || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		t.Fatal("disposable root required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container required")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("fresh network-none container required")
	}
	if syscall.Setgroups([]int{}) != nil {
		t.Fatal("empty fixture groups required")
	}
}

func openBundleFixture(t *testing.T) (*measuredBundleJournal, *np.JobCgroupJournal) {
	t.Helper()
	var files []*os.File
	for _, path := range []string{"/sys/fs/cgroup/provenance-fixture-jobs", "/state-input/journal", "/tmp/bundle-input", "/state-input/bundle-journal"} {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	cgroups, err := np.OpenJobCgroupJournal(files[0], files[1])
	if err != nil {
		t.Fatal(err)
	}
	j, err := openMeasuredBundleJournal(files[2], files[3], cgroups)
	if err != nil {
		cgroups.Close()
		t.Fatal(err)
	}
	return j, cgroups
}

func TestMeasuredBundleCrashHelper(t *testing.T) {
	mode := os.Getenv("PROVENANCE_BUNDLE_CRASH_MODE")
	if mode == "" {
		t.Skip("dedicated crash subprocess only")
	}
	requireMeasuredBundleFixture(t)
	j, cgroups := openBundleFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if j.recover(ctx) != nil {
		t.Fatal("pre-crash recovery")
	}
	job := measuredSpecJob(t)
	b, err := j.create(job)
	if err != nil {
		t.Fatal(err)
	}
	f, err := openBundleAt(b.directory, "retained-evidence", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("synthetic-owned-bundle"); err != nil {
		t.Fatal(err)
	}
	if f.Sync() != nil || f.Close() != nil || b.directory.Sync() != nil {
		t.Fatal("durable synthetic contents")
	}
	if mode == "retired-scope" {
		if cgroups.Cleanup(ctx, b.scope) != nil {
			t.Fatal("scope retirement before crash")
		}
	} else if mode == "live-scope" {
		fd, err := b.scope.LaunchFD(job)
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command("/bin/sleep", "30")
		child.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd()), Credential: &syscall.Credential{Uid: 65532, Gid: 65532, NoSetGroups: true}}
		if child.Start() != nil {
			t.Fatal("owned crash descendant")
		}
		fd.Close()
		if os.WriteFile(filepath.Join("/tmp/bundle-input", job.Lease.JobId, "live-pid"), []byte(strconv.Itoa(child.Process.Pid)+"\n"), 0600) != nil || b.directory.Sync() != nil {
			t.Fatal("owned descendant identity")
		}
		// No Pdeathsig: the known scope intentionally outlives this controller.
	} else {
		t.Fatal("unknown crash mode")
	}
	os.Exit(73)
}

func TestMeasuredBundleJournalKernelRecovery(t *testing.T) {
	requireMeasuredBundleFixture(t)
	t.Run("sealed-secret-tmpfs-materialization", measuredSecretStorageFixture)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	job := measuredSpecJob(t)
	for _, mode := range []string{"live-scope", "retired-scope"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMeasuredBundleCrashHelper$")
			cmd.Env = []string{"PATH=/usr/bin:/bin", "PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1", "PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE=1", "PROVENANCE_BUNDLE_CRASH_MODE=" + mode}
			err := cmd.Run()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
				t.Fatal("fixture did not reach deliberate crash", err)
			}
			if raw, err := os.ReadFile(filepath.Join("/tmp/bundle-input", job.Lease.JobId, "retained-evidence")); err != nil || string(raw) != "synthetic-owned-bundle" {
				t.Fatal("crash did not retain owned files")
			}
			pidfd := -1
			if mode == "live-scope" {
				raw, err := os.ReadFile(filepath.Join("/tmp/bundle-input", job.Lease.JobId, "live-pid"))
				if err != nil || len(raw) > 32 {
					t.Fatal("missing known descendant")
				}
				pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
				if err != nil || pid <= 1 {
					t.Fatal("invalid known descendant")
				}
				pidfd, err = unix.PidfdOpen(pid, 0)
				if err != nil {
					t.Fatal("known descendant did not survive crash")
				}
				defer unix.Close(pidfd)
				if exited, err := bundleFixtureExited(pidfd); err != nil || exited {
					t.Fatal("descendant already exited")
				}
			}
			j, cgroups := openBundleFixture(t)
			if j.recover(ctx) != nil {
				t.Fatal("cold bundle recovery")
			}
			if pidfd >= 0 {
				if exited, err := bundleFixtureExited(pidfd); err != nil || !exited {
					t.Fatal("known descendant survived recovery")
				}
			}
			if entries, err := os.ReadDir("/tmp/bundle-input"); err != nil || len(entries) != 0 {
				t.Fatal("recovered bundle remains")
			}
			if j.close() != nil || cgroups.Close() != nil {
				t.Fatal("recovered journals did not close")
			}
		})
	}
	t.Run("bounded-no-follow-cleanup", func(t *testing.T) {
		j, cgroups := openBundleFixture(t)
		defer cgroups.Close()
		defer j.close()
		if j.recover(ctx) != nil {
			t.Fatal("initial recovery")
		}
		b, err := j.create(job)
		if err != nil {
			t.Fatal(err)
		}
		defer j.cleanup(context.Background(), b)
		if j.check(b, job) != nil {
			t.Fatal("live durable ownership unavailable")
		}
		if other, err := openMeasuredBundleJournal(j.parent, j.state, cgroups); err == nil || other != nil {
			t.Fatal("simultaneous bundle journal admitted")
		}
		foreign := "/tmp/bundle-input/bundle-cleanup-foreign"
		if os.WriteFile(foreign, []byte("preserve"), 0600) != nil {
			t.Fatal("foreign fixture")
		}
		defer os.Remove(foreign)
		base := filepath.Join("/tmp/bundle-input", job.Lease.JobId)
		if os.Symlink(foreign, filepath.Join(base, "symlink")) != nil || os.Link(foreign, filepath.Join(base, "hardlink")) != nil || os.Mkdir(filepath.Join(base, "nested"), 0700) != nil || os.WriteFile(filepath.Join(base, "nested", "owned"), []byte("owned"), 0600) != nil {
			t.Fatal("owned cleanup fixture")
		}
		if j.cleanup(ctx, b) != nil || j.cleanup(ctx, b) != nil {
			t.Fatal("idempotent bundle cleanup")
		}
		if raw, err := os.ReadFile(foreign); err != nil || string(raw) != "preserve" {
			t.Fatal("cleanup followed a guest link")
		}
	})
	t.Run("foreign-directory-and-record-refusal", func(t *testing.T) {
		j, cgroups := openBundleFixture(t)
		defer cgroups.Close()
		defer j.close()
		if j.recover(ctx) != nil {
			t.Fatal("initial recovery")
		}
		path := filepath.Join("/tmp/bundle-input", job.Lease.JobId)
		if os.Mkdir(path, 0700) != nil {
			t.Fatal("foreign fixture directory")
		}
		if b, err := j.create(job); b != nil || err == nil {
			t.Fatal("foreign directory adopted")
		}
		if j.recover(ctx) == nil {
			t.Fatal("unrecorded directory ignored")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal("foreign directory removed")
		}
		if os.Remove(path) != nil {
			t.Fatal("exact foreign fixture removal")
		}
		bad := "/state-input/bundle-journal/unknown.json"
		if os.WriteFile(bad, []byte("{}\n"), 0600) != nil {
			t.Fatal("malformed fixture")
		}
		if j.recover(ctx) == nil {
			t.Fatal("malformed record accepted")
		}
		if raw, err := os.ReadFile(bad); err != nil || string(raw) != "{}\n" {
			t.Fatal("malformed evidence removed")
		}
		if os.Remove(bad) != nil || j.recover(ctx) != nil {
			t.Fatal("fixture recovery reset")
		}
	})
	t.Run("replaced-directory-refusal", func(t *testing.T) {
		j, cgroups := openBundleFixture(t)
		defer cgroups.Close()
		defer j.close()
		if j.recover(ctx) != nil {
			t.Fatal("initial recovery")
		}
		b, err := j.create(job)
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Join("/tmp/bundle-input", job.Lease.JobId)
		moved := "/tmp/bundle-input/retained-original"
		if os.Rename(base, moved) != nil || os.Mkdir(base, 0700) != nil || os.WriteFile(filepath.Join(base, "foreign"), []byte("preserve"), 0600) != nil {
			t.Fatal("directory replacement fixture")
		}
		if j.check(b, job) == nil || j.cleanup(ctx, b) == nil {
			t.Fatal("replacement adopted or removed")
		}
		if raw, err := os.ReadFile(filepath.Join(base, "foreign")); err != nil || string(raw) != "preserve" {
			t.Fatal("foreign replacement changed")
		}
		if os.Remove(filepath.Join(base, "foreign")) != nil || os.Remove(base) != nil || os.Rename(moved, base) != nil {
			t.Fatal("restore exact synthetic original")
		}
		if j.cleanup(ctx, b) != nil {
			t.Fatal("original ownership did not remain retryable")
		}
	})
	t.Run("mount-boundary-refusal", func(t *testing.T) {
		j, cgroups := openBundleFixture(t)
		defer cgroups.Close()
		defer j.close()
		if j.recover(ctx) != nil {
			t.Fatal("initial recovery")
		}
		b, err := j.create(job)
		if err != nil {
			t.Fatal(err)
		}
		defer j.cleanup(context.Background(), b)
		source := "/state-input/bundle-cleanup-mount-source"
		target := filepath.Join("/tmp/bundle-input", job.Lease.JobId, "mounted")
		if os.Mkdir(source, 0700) != nil || os.Mkdir(target, 0700) != nil || os.WriteFile(filepath.Join(source, "foreign"), []byte("preserve"), 0600) != nil {
			t.Fatal("mount fixture")
		}
		defer os.Remove(source)
		defer os.Remove(filepath.Join(source, "foreign"))
		if unix.Mount(source, target, "", unix.MS_BIND, "") != nil {
			t.Fatal("disposable bind unavailable")
		}
		mounted := true
		defer func() {
			if mounted {
				_ = unix.Unmount(target, 0)
			}
		}()
		if j.cleanup(ctx, b) == nil {
			t.Fatal("cleanup crossed bind mount")
		}
		if raw, err := os.ReadFile(filepath.Join(source, "foreign")); err != nil || string(raw) != "preserve" {
			t.Fatal("mounted foreign contents changed")
		}
		if unix.Unmount(target, 0) != nil {
			t.Fatal("owned bind removal")
		}
		mounted = false
		if j.cleanup(ctx, b) != nil {
			t.Fatal("bounded cleanup did not remain retryable")
		}
	})
	t.Run("preparation-failure-is-job-local", func(t *testing.T) {
		j, cgroups := openBundleFixture(t)
		defer cgroups.Close()
		defer j.close()
		if j.recover(ctx) != nil {
			t.Fatal("initial recovery")
		}
		b, err := j.create(job)
		if err != nil {
			t.Fatal(err)
		}
		defer j.cleanup(context.Background(), b)
		input, _ := measuredFixtureInput(t, ctx)
		bad := input
		bad.SHA256 = sha256.Sum256([]byte("wrong"))
		mapping := np.MappedIdentity{UID: 65532, GID: 65532, OverflowUID: 65533, OverflowGID: 65533}
		root := filepath.Join("/tmp/bundle-input", job.Lease.JobId, ".measured-root")
		command := measuredGuestCommand{Command: "/smoke"}
		if b.prepare(ctx, job, command, root, mapping, []measuredInput{bad}, 2<<20) == nil || b.checkPrepared(mapping) == nil {
			t.Fatal("bad input prepared or launched")
		}
		if b.prepare(ctx, job, command, root, mapping, []measuredInput{input}, 2<<20) == nil {
			t.Fatal("failed preparation resumed")
		}
		otherJob := proto.Clone(job).(*runnerv1.JobSpecification)
		otherJob.Lease.JobId = "80000000-0000-4000-8000-000000000001"
		otherJob.Lease.LeaseId = "90000000-0000-4000-8000-000000000001"
		otherJob.Attempt.AttemptId = "a0000000-0000-4000-8000-000000000001"
		other, err := j.create(otherJob)
		if err != nil {
			t.Fatal("bad input poisoned unrelated admission")
		}
		defer j.cleanup(context.Background(), other)
		otherMapping := np.MappedIdentity{UID: 65528, GID: 65528, OverflowUID: 65529, OverflowGID: 65529}
		otherRoot := filepath.Join("/tmp/bundle-input", otherJob.Lease.JobId, ".measured-root")
		if other.prepare(ctx, otherJob, command, otherRoot, otherMapping, []measuredInput{input}, 2<<20) != nil || other.checkPrepared(otherMapping) != nil {
			t.Fatal("unrelated preparation failed")
		}
		if j.cleanup(ctx, b) != nil || other.checkPrepared(otherMapping) != nil {
			t.Fatal("failed-job cleanup affected unrelated prepared job")
		}
	})
	for _, kind := range []string{"configuration", "resolver", "input", "identity", "private-root"} {
		t.Run("prepared-drift-"+kind, func(t *testing.T) {
			j, cgroups := openBundleFixture(t)
			defer cgroups.Close()
			defer j.close()
			if j.recover(ctx) != nil {
				t.Fatal("initial recovery")
			}
			b, err := j.create(job)
			if err != nil {
				t.Fatal(err)
			}
			defer j.cleanup(context.Background(), b)
			input, _ := measuredFixtureInput(t, ctx)
			mapping := np.MappedIdentity{UID: 65532, GID: 65532, OverflowUID: 65533, OverflowGID: 65533}
			base := filepath.Join("/tmp/bundle-input", job.Lease.JobId)
			if b.prepare(ctx, job, measuredGuestCommand{Command: "/smoke"}, filepath.Join(base, ".measured-root"), mapping, []measuredInput{input}, 2<<20) != nil || b.checkPrepared(mapping) != nil {
				t.Fatal("positive preparation")
			}
			switch kind {
			case "resolver":
				if os.Chmod(filepath.Join(base, "resolv.conf"), 0644) != nil {
					t.Fatal("resolver drift fixture")
				}
			case "configuration":
				if os.Chmod(filepath.Join(base, "config.json"), 0644) != nil {
					t.Fatal("configuration drift fixture")
				}
			case "input":
				if os.Chmod(filepath.Join(base, "inputs", "sample"), 0644) != nil {
					t.Fatal("input drift fixture")
				}
			case "identity":
				wrong := mapping
				wrong.UID = 65530
				if b.checkPrepared(wrong) == nil {
					t.Fatal("foreign mapping accepted")
				}
			case "private-root":
				path := filepath.Join(base, ".measured-root")
				if os.Rename(path, path+"-old") != nil || os.Mkdir(path, 0700) != nil || os.Chown(path, int(mapping.UID), int(mapping.GID)) != nil {
					t.Fatal("private root replacement fixture")
				}
			}
			if b.checkPrepared(mapping) == nil {
				t.Fatal("prepared identity drift accepted")
			}
			if kind == "configuration" {
				if os.Chmod(filepath.Join(base, "config.json"), 0444) != nil {
					t.Fatal("restore fixture mode")
				}
			}
			if kind == "input" {
				// Input drift and resolver drift both remain permanently refused.
				if os.Chmod(filepath.Join(base, "inputs", "sample"), 0444) != nil {
					t.Fatal("restore fixture mode")
				}
			}
			if kind == "resolver" {
				if os.Chmod(filepath.Join(base, "resolv.conf"), 0444) != nil {
					t.Fatal("restore resolver fixture mode")
				}
			}
			if b.checkPrepared(mapping) == nil {
				t.Fatal("failed prepared proof resumed")
			}
		})
	}
}

func bundleFixtureExited(fd int) (bool, error) {
	for attempt := 0; attempt < 8; attempt++ {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 0)
		if err == unix.EINTR {
			continue
		}
		return n > 0 && fds[0].Revents&unix.POLLIN != 0, err
	}
	return false, unix.EINTR
}
