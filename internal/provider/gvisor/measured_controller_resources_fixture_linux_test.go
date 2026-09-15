//go:build linux

package gvisor

import (
	"os"
	"strconv"
	"testing"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

const controllerResourceFixturePath = "/sys/fs/cgroup/provenance-fixture-jobs/"

// This configures only the explicitly created network-none container's private
// test cgroup. Production provisioning is a separate guarded operation.
func measuredControllerResourcesFixture(t *testing.T, maximum *p.ResourceLimits) {
	t.Helper()
	if os.Getenv("PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE") != "1" || os.Getuid() != 0 {
		t.Fatal("explicit disposable controller resource fixture required")
	}
	values := [][2]string{{"cpu.max", strconv.FormatUint(2*uint64(maximum.CpuMillis)*100, 10) + " 100000"}, {"cpu.max.burst", "0"}, {"memory.max", strconv.FormatUint(2*maximum.MemoryBytes, 10)}, {"memory.swap.max", "0"}, {"pids.max", strconv.FormatUint(2*(uint64(maximum.ProcessCount)+np.MappedRuntimeProcessReserve), 10)}, {"cgroup.max.descendants", "2"}, {"cgroup.max.depth", "1"}, {"memory.oom.group", "1"}}
	original := map[string][]byte{}
	for _, value := range values {
		raw, err := os.ReadFile(controllerResourceFixturePath + value[0])
		if err != nil || len(raw) > 4096 {
			t.Fatal("original controller control")
		}
		original[value[0]] = raw
	}
	t.Cleanup(func() {
		for _, value := range values {
			if os.WriteFile(controllerResourceFixturePath+value[0], original[value[0]], 0600) != nil {
				t.Error("restore exact controller fixture control")
			}
		}
	})
	for _, value := range values {
		if os.WriteFile(controllerResourceFixturePath+value[0], []byte(value[1]), 0600) != nil {
			t.Fatal("controller resource provisioning")
		}
	}
}
