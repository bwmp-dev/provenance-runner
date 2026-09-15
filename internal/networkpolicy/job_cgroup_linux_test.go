//go:build linux

package networkpolicy

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func TestJobCgroupRefusesUnownedInput(t *testing.T) {
	_, job, _, _, _, _ := authorityFixture(t)
	if scope, err := CreateJobCgroup(job, nil); scope != nil || err == nil {
		t.Fatal("missing parent accepted")
	}
	ordinary, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	if scope, err := CreateJobCgroup(job, ordinary); scope != nil || err == nil {
		t.Fatal("ordinary directory accepted")
	}
	var absent *JobCgroup
	if fd, err := absent.LaunchFD(job); fd != nil || err == nil {
		t.Fatal("absent scope granted launch")
	}
	if absent.Cleanup(context.Background()) != nil {
		t.Fatal("nil cleanup")
	}
	for _, raw := range []string{"", "populated 1\nfrozen 0\n", "populated 0\npopulated 0\n", "populated\n", "frozen 0\n"} {
		if cgroupEmpty(raw) {
			t.Fatal("invalid empty claim", raw)
		}
	}
	if !cgroupEmpty("populated 0\nfrozen 0\n") {
		t.Fatal("empty kernel observation refused")
	}
}

func TestJobCgroupKernelLifecycle(t *testing.T) {
	if os.Getenv("PROVENANCE_DISPOSABLE_JOB_CGROUP_FIXTURE") != "1" {
		t.Skip("explicit disposable cgroup fixture required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("fresh root fixture required")
	}
	_, job, _, _, _, _ := authorityFixture(t)
	parent, err := os.Open("/sys/fs/cgroup/provenance-fixture-jobs")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	root, err := os.Open("/sys/fs/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	if unexpected, err := CreateJobCgroup(job, root); unexpected != nil || err == nil {
		t.Fatal("namespace root accepted as provisioned parent")
	}
	root.Close()
	siblingJob := proto.Clone(job).(*p.JobSpecification)
	siblingJob.Lease.JobId = "70000000-0000-4000-8000-000000000002"
	sibling, err := CreateJobCgroup(siblingJob, parent)
	if sibling != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := sibling.Cleanup(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	siblingFD, err := sibling.LaunchFD(siblingJob)
	if err != nil {
		t.Fatal(err)
	}
	defer siblingFD.Close()
	siblingProcess := exec.Command("/bin/sleep", "60")
	siblingProcess.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(siblingFD.Fd()), Credential: &syscall.Credential{Uid: 60002, Gid: 60002, NoSetGroups: true}}
	if err := siblingProcess.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sibling.Cleanup(ctx); err != nil {
			t.Error(err)
		}
		_ = siblingProcess.Wait()
	})
	scope, err := CreateJobCgroup(job, parent)
	if scope != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := scope.Cleanup(ctx); err != nil {
				t.Error("owned cleanup", err)
			}
		})
	}
	if err != nil {
		t.Fatal("new leaf unavailable", err)
	}
	if other, err := CreateJobCgroup(job, parent); other != nil || err == nil {
		t.Fatal("existing scope adopted")
	}
	fd, err := scope.LaunchFD(job)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	// An unprivileged synthetic descendant outlives its launcher. No arbitrary
	// host command or workload input is accepted by the production boundary.
	cmd := exec.Command("/bin/sh", "-c", "sleep 60 & echo ready; exit 0")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd()), Credential: &syscall.Credential{Uid: 60000, Gid: 60000, NoSetGroups: true}}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal("birth in scope", err)
	}
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatal("descendant fixture unavailable", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	raw, err := readCgroupControl(scope.scope, "cgroup.events")
	if err != nil || cgroupEmpty(raw) {
		t.Fatal("launcher exit falsely counted as whole-tree cleanup")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if scope.Cleanup(cancelled) == nil {
		t.Fatal("cancelled cleanup succeeded")
	}
	if next, err := scope.LaunchFD(job); next != nil || err == nil {
		t.Fatal("stopping scope resumed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := scope.Cleanup(ctx); err != nil {
		t.Fatal("kill descendants and remove", err)
	}
	if _, err := os.Stat("/sys/fs/cgroup/provenance-fixture-jobs/" + scope.name); !os.IsNotExist(err) {
		t.Fatal("owned directory remains")
	}
	late := exec.Command("/bin/true")
	late.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	if err := late.Run(); err == nil {
		t.Fatal("retained FD revived removed scope")
	}
	if err := scope.Cleanup(context.Background()); err != nil {
		t.Fatal("cleanup not idempotent", err)
	}
	if _, err := os.Stat("/sys/fs/cgroup/provenance-fixture-controller/cgroup.procs"); err != nil {
		t.Fatal("controller scope changed", err)
	}
	if err := siblingProcess.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("sibling was killed", err)
	}
	if fresh, err := sibling.LaunchFD(siblingJob); err != nil {
		t.Fatal("sibling scope invalidated", err)
	} else {
		fresh.Close()
	}
	wrong := proto.Clone(siblingJob).(*p.JobSpecification)
	wrong.Lease.LeaseId = "70000000-0000-4000-8000-000000000003"
	if unexpected, err := sibling.LaunchFD(wrong); unexpected != nil || err == nil {
		t.Fatal("wrong lease accepted")
	}
	if unexpected, err := sibling.LaunchFD(siblingJob); unexpected != nil || err == nil {
		t.Fatal("wrong-lease refusal revived")
	}
	t.Log("owned descendant killed, directory removed, stale launch FD refused, controller survived")
}
