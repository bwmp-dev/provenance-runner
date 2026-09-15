//go:build linux

package gvisor

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func networkMeasuredArguments() []string {
	job := "10000000-0000-4000-8000-000000000001"
	return []string{job, "65532", "65532", "65533", "65533", filepath.Join("/fixture", job, ".measured-root"), strings.Repeat("a", 64), "embedded-executable"}
}

func TestMeasuredNetworkHandoffHasClosedArguments(t *testing.T) {
	args := networkMeasuredArguments()
	_, run, ok := measuredNetworkInputs(args)
	if !ok {
		t.Fatal("valid bounded handoff rejected")
	}
	for _, required := range []string{"--rootless=false", "--network=sandbox", "--net-raw=false", "--host-uds=none", "--host-fifo=none", "--allow-suid=false", "--directfs=false", "--gofer-network-namespace=new"} {
		if !slices.Contains(run, required) {
			t.Fatal("missing fixed safety option", required)
		}
	}
	if embeddedOptions(run) {
		t.Fatal("network handoff silently admitted through legacy launcher")
	}
	for _, index := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8} {
		changed := append([]string(nil), args...)
		if index == 8 {
			changed = append(changed, "--network=host")
		} else {
			changed[index] = "secret-value"
		}
		if _, _, ok := measuredNetworkInputs(changed); ok {
			t.Fatal("hostile argument accepted")
		}
		var output bytes.Buffer
		if RunMeasuredNetworkChild(changed, &output) != runscFailureExitCode || strings.Contains(output.String(), "secret-value") {
			t.Fatal("hostile input echoed or executed")
		}
	}
	for _, replacement := range []string{"0", "065532", "4294967295", "65533"} {
		changed := append([]string(nil), args...)
		changed[1] = replacement
		if _, _, ok := measuredNetworkInputs(changed); ok {
			t.Fatal("invalid mapped identity accepted")
		}
	}
	changed := append([]string(nil), args...)
	changed[5] = "/fixture/foreign/.measured-root"
	if _, _, ok := measuredNetworkInputs(changed); ok {
		t.Fatal("cross-job mount target accepted")
	}
}

func TestMeasuredNetworkRequiresExactTwoIDMaps(t *testing.T) {
	if !exactNetworkMapping([]byte("0 65532 1\n65534 65533 1\n"), 65532, 65533) {
		t.Fatal("exact mapping refused")
	}
	for _, mapping := range []string{"0 65532 1", "0 0 1\n65534 65533 1", "0 65532 2\n65534 65533 1", "0 65532 1\n1 65533 1", "0 65532 1\n65534 65533 2", "0 65532 1\n65534 65533 1\n65535 65534 1"} {
		if exactNetworkMapping([]byte(mapping), 65532, 65533) {
			t.Fatal("unsafe mapping accepted")
		}
	}
}

func TestMeasuredNetworkLaunchGateIsBoundedAndExact(t *testing.T) {
	for _, message := range []string{"s", "", "x", "ss"} {
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := write.Write([]byte(message)); err != nil {
			t.Fatal(err)
		}
		write.Close()
		got := awaitMeasuredNetworkGate(read, time.Now().Add(time.Second))
		read.Close()
		if got != (message == "s") {
			t.Fatal("ambiguous launch gate admitted", message)
		}
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	start := time.Now()
	if awaitMeasuredNetworkGate(read, start.Add(20*time.Millisecond)) || time.Since(start) > time.Second {
		t.Fatal("missing launch authorization did not time out")
	}
	file, err := os.CreateTemp(t.TempDir(), "not-a-gate")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if awaitMeasuredNetworkGate(file, time.Now().Add(time.Second)) {
		t.Fatal("regular file substituted for launch gate")
	}
}

func TestMeasuredNetworkReadinessCannotAuthorizeLaunch(t *testing.T) {
	for _, message := range []string{"r", "", "s", "rr"} {
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := write.Write([]byte(message)); err != nil {
			t.Fatal(err)
		}
		write.Close()
		got := awaitMeasuredNetworkToken(read, time.Now().Add(time.Second), 'r')
		read.Close()
		if got != (message == "r") {
			t.Fatal("ambiguous readiness accepted", message)
		}
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if _, err := write.Write([]byte{'r'}); err != nil {
		t.Fatal(err)
	}
	if awaitMeasuredNetworkToken(read, time.Now().Add(20*time.Millisecond), 'r') {
		t.Fatal("readiness without EOF accepted")
	}
}
