package gvisor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

func TestCgroupUsageRootsIncludeDelegatedSibling(t *testing.T) {
	roots := cgroupUsageRoots("/provenance-ci-1/runner", "container")
	want := "/sys/fs/cgroup/provenance-ci-1/provenance/container"
	if len(roots) != 3 || roots[1] != want {
		t.Fatalf("roots = %#v, want delegated sibling %q", roots, want)
	}
}

func TestReadCgroupUsageUsesMeasuredCumulativeCounters(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"cpu.stat":    "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n",
		"memory.peak": "987654\n",
		"io.stat":     "8:0 rbytes=10 wbytes=20 rios=1 wios=2\n8:1 rbytes=30 wbytes=40\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	usage, ok := readCgroupUsageRoot(root)
	if !ok || usage.CPUTime != 123456*time.Microsecond || usage.PeakMemoryBytes != 987654 || usage.DiskReadBytes != 40 || usage.DiskWriteBytes != 60 || usage.NetworkReceiveBytes != 0 || usage.NetworkTransmitBytes != 0 {
		t.Fatalf("usage = %#v available=%v", usage, ok)
	}
}

func TestReadCgroupUsageFallsBackToCurrentMemory(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  uint64
	}{
		{name: "peak preferred", files: map[string]string{"memory.peak": "90\n", "memory.current": "70\n"}, want: 90},
		{name: "current when peak missing", files: map[string]string{"memory.current": "70\n"}, want: 70},
		{name: "current when peak invalid", files: map[string]string{"memory.peak": "max\n", "memory.current": "70\n"}, want: 70},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range test.files {
				if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			usage, ok := readCgroupUsageRoot(root)
			if !ok || usage.PeakMemoryBytes != test.want {
				t.Fatalf("usage = %#v available=%v, want memory %d", usage, ok, test.want)
			}
		})
	}
}

func TestReadPIDMaxEventsFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pids.events")
	for _, test := range []struct {
		content string
		want    uint64
		ok      bool
	}{
		{content: "max 0\n", want: 0, ok: true},
		{content: "max 17\n", want: 17, ok: true},
		{content: "max nope\n", ok: false},
		{content: "other 1\n", ok: false},
	} {
		if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, ok := readPIDMaxEvents(path)
		if got != test.want || ok != test.ok {
			t.Errorf("readPIDMaxEvents(%q) = %d, %t; want %d, %t", test.content, got, ok, test.want, test.ok)
		}
	}
}

func TestMergeMeasuredUsageNeverMovesCumulativeCountersBackward(t *testing.T) {
	current := execution.ResourceUsage{CPUTime: 2 * time.Second, PeakMemoryBytes: 20, DiskReadBytes: 30, DiskWriteBytes: 40}
	if mergeMeasuredUsage(&current, execution.ResourceUsage{CPUTime: time.Second, PeakMemoryBytes: 10, DiskReadBytes: 50}) != true {
		t.Fatal("increasing disk counter was not detected")
	}
	if current.CPUTime != 2*time.Second || current.PeakMemoryBytes != 20 || current.DiskReadBytes != 50 || current.DiskWriteBytes != 40 {
		t.Fatalf("merged usage = %#v", current)
	}
}
