package gvisor

import (
	"bufio"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

const usageSampleInterval = 250 * time.Millisecond

func (e *preparedEnvironment) sampleUsageUntil(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(usageSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			e.sampleUsage()
		}
	}
}

func (e *preparedEnvironment) sampleUsage() {
	roots := cgroupUsageRootsForEnvironment(e.containerID, e.provider.config.SystemdCgroupRoot)
	e.sampleUsageRoots(roots)
}

func (e *preparedEnvironment) sampleUsageRoots(roots []string) {
	usage, ok := readCgroupUsageRoots(roots)
	denials, denialEvidenceAvailable := readOuterPIDDenialsRoots(roots)
	if !ok && !denialEvidenceAvailable {
		return
	}
	e.usageMu.Lock()
	if e.provider.config.CgroupDriver == CgroupDriverSystemdUser {
		e.scopeCgroupObserved = true
	}
	changed := ok && mergeMeasuredUsage(&e.usage, usage)
	if denialEvidenceAvailable {
		e.pidDenialEvidenceAvailable = true
		if denials > e.outerPIDDenials {
			e.outerPIDDenials = denials
		}
	}
	observer := e.observer
	current := e.usage
	e.usageMu.Unlock()
	if changed && observer != nil {
		observer.ObserveUsage(current)
	}
}

func mergeMeasuredUsage(current *execution.ResourceUsage, measured execution.ResourceUsage) bool {
	changed := false
	if measured.CPUTime > current.CPUTime {
		current.CPUTime, changed = measured.CPUTime, true
	}
	for destination, value := range map[*uint64]uint64{
		&current.PeakMemoryBytes:      measured.PeakMemoryBytes,
		&current.DiskReadBytes:        measured.DiskReadBytes,
		&current.DiskWriteBytes:       measured.DiskWriteBytes,
		&current.NetworkReceiveBytes:  measured.NetworkReceiveBytes,
		&current.NetworkTransmitBytes: measured.NetworkTransmitBytes,
	} {
		if value > *destination {
			*destination, changed = value, true
		}
	}
	return changed
}

func readCgroupUsage(containerID, systemdCgroupRoot string) (execution.ResourceUsage, bool) {
	return readCgroupUsageRoots(cgroupUsageRootsForEnvironment(containerID, systemdCgroupRoot))
}

func readCgroupUsageRoots(roots []string) (execution.ResourceUsage, bool) {
	for _, root := range roots {
		if !strings.HasPrefix(root, "/sys/fs/cgroup/") {
			// Tests exercise the parser with owner-controlled temporary roots.
			if !filepath.IsAbs(root) {
				continue
			}
		}
		if usage, found := readCgroupUsageRoot(root); found {
			return usage, true
		}
	}
	return execution.ResourceUsage{}, false
}

func readOuterPIDDenials(containerID, systemdCgroupRoot string) (uint64, bool) {
	return readOuterPIDDenialsRoots(cgroupUsageRootsForEnvironment(containerID, systemdCgroupRoot))
}

func readOuterPIDDenialsRoots(roots []string) (uint64, bool) {
	for _, root := range roots {
		if !filepath.IsAbs(root) {
			continue
		}
		if denials, found := readPIDMaxEvents(filepath.Join(root, "pids.events")); found {
			return denials, true
		}
	}
	return 0, false
}

func cgroupUsageRootsForEnvironment(containerID, systemdCgroupRoot string) []string {
	if systemdCgroupRoot != "" {
		return []string{systemdCgroupPath(systemdCgroupRoot, containerID)}
	}
	relative, ok := currentUnifiedCgroup()
	if !ok {
		return nil
	}
	return cgroupUsageRoots(relative, containerID, "")
}

func readPIDMaxEvents(path string) (uint64, bool) {
	content, ok := readSmallFile(path)
	if !ok {
		return 0, false
	}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "max" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			return value, err == nil
		}
	}
	return 0, false
}

func cgroupUsageRoots(relative, containerID, systemdCgroupRoot string) []string {
	if systemdCgroupRoot != "" {
		return []string{systemdCgroupPath(systemdCgroupRoot, containerID)}
	}
	roots := []string{
		filepath.Clean(filepath.Join("/sys/fs/cgroup", relative, "provenance", containerID)),
		filepath.Clean(filepath.Join("/sys/fs/cgroup", filepath.Dir(relative), "provenance", containerID)),
		filepath.Clean(filepath.Join("/sys/fs/cgroup", "provenance", containerID)),
	}
	return roots
}

func readCgroupUsageRoot(root string) (execution.ResourceUsage, bool) {
	var usage execution.ResourceUsage
	found := false
	if content, ok := readSmallFile(filepath.Join(root, "cpu.stat")); ok {
		for _, line := range strings.Split(content, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "usage_usec" {
				if value, err := strconv.ParseUint(fields[1], 10, 64); err == nil && value <= math.MaxInt64/uint64(time.Microsecond) {
					usage.CPUTime = time.Duration(value) * time.Microsecond
					found = true
				}
			}
		}
	}
	if value, ok := readCgroupUint(root, "memory.peak"); ok {
		usage.PeakMemoryBytes = value
		found = true
	} else if value, ok := readCgroupUint(root, "memory.current"); ok {
		// Some delegated cgroup v2 environments do not expose memory.peak.
		// memory.current is a real (though not historical-peak) measurement and
		// the sampler's monotonic merge retains the largest observed value.
		usage.PeakMemoryBytes = value
		found = true
	}
	if content, ok := readSmallFile(filepath.Join(root, "io.stat")); ok {
		for _, line := range strings.Split(content, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			for _, field := range fields[1:] {
				key, raw, present := strings.Cut(field, "=")
				if !present {
					continue
				}
				value, err := strconv.ParseUint(raw, 10, 64)
				if err != nil {
					continue
				}
				switch key {
				case "rbytes":
					usage.DiskReadBytes = saturatingUsageAdd(usage.DiskReadBytes, value)
				case "wbytes":
					usage.DiskWriteBytes = saturatingUsageAdd(usage.DiskWriteBytes, value)
				}
			}
		}
		found = true
	}
	// Hosted v1 enforces network=none. Zero network counters are therefore an
	// observed policy outcome; no traffic values are derived from host activity.
	return usage, found
}

func readCgroupUint(root, name string) (uint64, bool) {
	content, ok := readSmallFile(filepath.Join(root, name))
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimSpace(content), 10, 64)
	return value, err == nil
}

func saturatingUsageAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}

func currentUnifiedCgroup() (string, bool) {
	file, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return "", false
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 64<<10))
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "0::") {
			return strings.TrimPrefix(scanner.Text(), "0::"), true
		}
	}
	return "", false
}

func readSmallFile(path string) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 64<<10))
	return string(content), err == nil
}
