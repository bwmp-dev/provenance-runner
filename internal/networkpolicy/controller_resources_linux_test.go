//go:build linux

package networkpolicy

import (
	"testing"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

func TestControllerResourceCeilingCoversBothOwnedRoles(t *testing.T) {
	maximum := &p.ResourceLimits{CpuMillis: 2000, MemoryBytes: 1 << 30, ProcessCount: 256, DiskBytes: 2 << 20}
	values, err := controllerResourceValues(maximum)
	if err != nil || values != ([8]string{"400000 100000\n", "0\n", "2147483648\n", "0\n", "546\n", "2\n", "1\n", "1\n"}) {
		t.Fatal("aggregate profile mismatch", err)
	}
	for _, bad := range []*p.ResourceLimits{nil, {}, {CpuMillis: 2000, MemoryBytes: ^uint64(0), ProcessCount: 256, DiskBytes: 2 << 20}} {
		if _, err := controllerResourceValues(bad); err == nil {
			t.Fatal("invalid aggregate ceiling")
		}
	}
	if r, err := RetainControllerResources(nil, maximum); r != nil || err == nil {
		t.Fatal("unowned aggregate parent")
	}
	if scope, err := (&JobCgroupJournal{}).CreateForController(nil, &ControllerResources{}); scope != nil || err == nil {
		t.Fatal("empty parent proof")
	}
	var absent *ControllerResources
	if absent.Validate() == nil || absent.Close() != nil {
		t.Fatal("nil aggregate proof")
	}
	if (&ControllerResources{}).Validate() == nil {
		t.Fatal("empty aggregate proof")
	}
}
