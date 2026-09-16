//go:build linux

package gvisor

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMeasuredRuntimeCPUSet(t *testing.T) {
	var available unix.CPUSet
	for _, cpu := range []int{3, 7, 19, 63, 900} {
		available.Set(cpu)
	}
	for _, test := range []struct {
		millis uint32
		count  int
	}{{10, 2}, {500, 2}, {1000, 2}, {2000, 2}, {2001, 3}, {4000, 4}, {64000, 5}} {
		selected, err := measuredRuntimeCPUSet(available, test.millis)
		if err != nil || selected.Count() != test.count {
			t.Fatalf("millis=%d count=%d err=%v", test.millis, selected.Count(), err)
		}
		for cpu := 0; cpu < 1024; cpu++ {
			if selected.IsSet(cpu) && !available.IsSet(cpu) {
				t.Fatal("affinity expanded")
			}
		}
	}
	var single unix.CPUSet
	single.Set(17)
	if selected, err := measuredRuntimeCPUSet(single, 2000); err != nil || selected != single {
		t.Fatal("single inherited CPU not preserved")
	}
	for _, millis := range []uint32{0, 9, 64001, ^uint32(0)} {
		if _, err := measuredRuntimeCPUSet(available, millis); err == nil {
			t.Fatal("invalid CPU allowance")
		}
	}
	if _, err := measuredRuntimeCPUSet(unix.CPUSet{}, 2000); err == nil {
		t.Fatal("empty inherited mask")
	}
	for _, value := range []string{"0", "9", "64001", "02000", "+2000", "2e3", "2000\n", "4294967296"} {
		args := networkMeasuredArguments()
		args[8] = value
		if _, _, ok := measuredNetworkInputs(args); ok {
			t.Fatal("noncanonical CPU argument accepted")
		}
	}
}

func TestMeasuredRuntimeAffinitySurvivesExec(t *testing.T) {
	const marker = "PROVENANCE_TEST_CPU_AFFINITY"
	if stage := os.Getenv(marker); stage != "" {
		if stage == "observed" {
			want, err := strconv.Atoi(os.Getenv("PROVENANCE_TEST_CPU_COUNT"))
			var mask unix.CPUSet
			if err != nil || want < 1 || want > 2 || unix.SchedGetaffinity(0, &mask) != nil || mask.Count() != want || runtime.NumCPU() != want {
				t.Fatal("exec did not retain bounded CPU visibility")
			}
			return
		}
		if stage != "apply" {
			t.Fatal("invalid fixture stage")
		}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var inherited unix.CPUSet
		if unix.SchedGetaffinity(0, &inherited) != nil || limitMeasuredRuntimeCPUs(500) != nil {
			t.Fatal("affinity preparation")
		}
		path, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		err = syscall.Exec(path, []string{path, "-test.run=^TestMeasuredRuntimeAffinitySurvivesExec$"}, []string{"PATH=/usr/bin:/bin", marker + "=observed", "PROVENANCE_TEST_CPU_COUNT=" + strconv.Itoa(min(2, inherited.Count()))})
		t.Fatal("fixture exec returned", err)
	}
	var before, after unix.CPUSet
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if unix.SchedGetaffinity(0, &before) != nil {
		t.Fatal("parent affinity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, path, "-test.run=^TestMeasuredRuntimeAffinitySurvivesExec$")
	command.Env = []string{"PATH=/usr/bin:/bin", marker + "=apply"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("affinity subprocess: %v %s", err, output)
	}
	if unix.SchedGetaffinity(0, &after) != nil || before != after {
		t.Fatal("controller affinity changed")
	}
}
