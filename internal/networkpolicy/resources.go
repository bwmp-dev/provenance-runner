package networkpolicy

import (
	"errors"
	"math/bits"
	"strconv"
	"strings"
)

var ErrResources = errors.New("network_runtime_resource_boundary_unavailable")

// MappedRuntimeProcessReserve matches the bounded gVisor runtime/gofer reserve.
// It is not an additional guest process allowance.
const MappedRuntimeProcessReserve uint64 = 17

type resourceLimits struct{ cpuMillis, memoryBytes, processes uint64 }
type resourceState struct{ quota, period, memory, processes uint64 }

func resourceNumber(raw string, zero bool) (uint64, bool) {
	if len(raw) > 32 {
		return 0, false
	}
	value := strings.TrimSuffix(raw, "\n")
	n, err := strconv.ParseUint(value, 10, 64)
	return n, err == nil && (zero || n > 0) && strconv.FormatUint(n, 10) == value
}

func readResourceState(values map[string]string, ceiling resourceLimits) (resourceState, error) {
	var state resourceState
	if len(values) != 6 || ceiling.cpuMillis == 0 || ceiling.memoryBytes == 0 || ceiling.processes == 0 || ceiling.processes > 4096+MappedRuntimeProcessReserve || values["cgroup.type"] != "domain\n" || values["memory.swap.max"] != "0\n" || values["cpu.max.burst"] != "0\n" {
		return state, ErrResources
	}
	var ok bool
	state.memory, ok = resourceNumber(values["memory.max"], false)
	if !ok || state.memory > ceiling.memoryBytes {
		return resourceState{}, ErrResources
	}
	state.processes, ok = resourceNumber(values["pids.max"], false)
	if !ok || state.processes > ceiling.processes {
		return resourceState{}, ErrResources
	}
	fields := strings.Split(strings.TrimSuffix(values["cpu.max"], "\n"), " ")
	if len(fields) != 2 {
		return resourceState{}, ErrResources
	}
	state.quota, ok = resourceNumber(fields[0], false)
	if !ok {
		return resourceState{}, ErrResources
	}
	state.period, ok = resourceNumber(fields[1], false)
	if !ok || state.period < 1000 || state.period > 1_000_000 {
		return resourceState{}, ErrResources
	}
	// Compare quota/period against millicores without overflowing either side.
	lh, ll := bits.Mul64(state.quota, 1000)
	rh, rl := bits.Mul64(ceiling.cpuMillis, state.period)
	if lh > rh || (lh == rh && ll > rl) {
		return resourceState{}, ErrResources
	}
	return state, nil
}
