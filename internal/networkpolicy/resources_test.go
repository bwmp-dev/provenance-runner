package networkpolicy

import (
	"maps"
	"math"
	"testing"
)

func resourceValues() map[string]string {
	return map[string]string{"cgroup.type": "domain\n", "memory.max": "1073741824\n", "memory.swap.max": "0\n", "cpu.max": "200000 100000\n", "cpu.max.burst": "0\n", "pids.max": "273\n"}
}

func TestResourceLimitsRequireFiniteOriginalCeilings(t *testing.T) {
	ceiling := resourceLimits{2000, 2 << 30, 256 + MappedRuntimeProcessReserve}
	values := resourceValues()
	state, err := readResourceState(values, ceiling)
	if err != nil || state.memory != 1<<30 || state.quota != 200000 || state.processes != 273 {
		t.Fatal("finite enforcement refused", err)
	}
	for key, replacements := range map[string][]string{
		"cgroup.type":     {"domain threaded\n", "threaded\n", "domain invalid\n", ""},
		"memory.max":      {"max\n", "0\n", "2147483649\n", "-1\n", "01\n", " 1024\n", "1024\nforeign\n"},
		"memory.swap.max": {"max\n", "1\n", "00\n"},
		"cpu.max":         {"max 100000\n", "200001 100000\n", "0 100000\n", "200000 0\n", "200000 999\n", "200000 1000001\n", "200000  100000\n", "200000 100000 0\n", "18446744073709551615 100000\n"},
		"cpu.max.burst":   {"1\n", "max\n", ""},
		"pids.max":        {"max\n", "0\n", "274\n", "+273\n", "18446744073709551616\n"},
	} {
		for _, value := range replacements {
			t.Run(key+value, func(t *testing.T) {
				changed := maps.Clone(values)
				changed[key] = value
				if _, err := readResourceState(changed, ceiling); err != ErrResources {
					t.Fatal("unsafe enforcement accepted")
				}
			})
		}
	}
	for key := range values {
		changed := maps.Clone(values)
		delete(changed, key)
		if _, err := readResourceState(changed, ceiling); err != ErrResources {
			t.Fatal("missing control accepted")
		}
	}
	for _, bad := range []resourceLimits{{0, 2 << 30, 273}, {2000, 0, 273}, {2000, 2 << 30, 0}, {2000, 2 << 30, 4114}} {
		if _, err := readResourceState(values, bad); err != ErrResources {
			t.Fatal("invalid original ceiling accepted")
		}
	}
	// Multiplication overflow must never turn an unbounded quota into a small one.
	changed := maps.Clone(values)
	changed["cpu.max"] = "18446744073709551615 1000000\n"
	if _, err := readResourceState(changed, resourceLimits{2000, math.MaxUint64, 273}); err != ErrResources {
		t.Fatal("CPU cross-product overflow accepted")
	}
}
