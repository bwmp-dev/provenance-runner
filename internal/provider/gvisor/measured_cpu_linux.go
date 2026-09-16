//go:build linux

package gvisor

import "golang.org/x/sys/unix"

// measuredRuntimeCPUSet limits runtime parallelism, not CPU-time authority.
// The independently owned cgroup's unchanged cpu.max remains the enforcement
// boundary. With runsc --ignore-cgroups, CPU visibility otherwise follows the
// whole host, allowing a small job to create host-sized runtime thread pools.
// Match runsc's quota-derived convention: ceil(millicores/1000), at least two
// visible CPUs when available. Never add a CPU outside the inherited mask.
func measuredRuntimeCPUSet(available unix.CPUSet, millis uint32) (unix.CPUSet, error) {
	var selected unix.CPUSet
	if millis < 10 || millis > 64000 || available.Count() == 0 {
		return selected, ErrMeasuredNetworkLaunch
	}
	count := max(2, int((millis+999)/1000))
	for cpu := 0; cpu < len(available)*64 && selected.Count() < count; cpu++ {
		if available.IsSet(cpu) {
			selected.Set(cpu)
		}
	}
	if selected.Count() == 0 {
		return selected, ErrMeasuredNetworkLaunch
	}
	return selected, nil
}

// The caller must remain OS-thread-locked through exec and exit on failure.
func limitMeasuredRuntimeCPUs(millis uint32) error {
	var available, observed unix.CPUSet
	if unix.SchedGetaffinity(0, &available) != nil {
		return ErrMeasuredNetworkLaunch
	}
	selected, err := measuredRuntimeCPUSet(available, millis)
	if err != nil || unix.SchedSetaffinity(0, &selected) != nil || unix.SchedGetaffinity(0, &observed) != nil || observed != selected {
		return ErrMeasuredNetworkLaunch
	}
	return nil
}
