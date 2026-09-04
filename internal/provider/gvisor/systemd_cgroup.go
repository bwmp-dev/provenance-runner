package gvisor

import (
	"errors"
	"strconv"
)

type cgroupLimits struct {
	memoryBytes int64
	cpuMillis   int64
	pids        int64
}

func (p *Provider) wrapRunCommand(invocation command, limits cgroupLimits, containerID string) (command, error) {
	if p.config.CgroupDriver != CgroupDriverSystemdUser {
		return invocation, nil
	}
	if !validContainerID(containerID) {
		return command{}, errors.New("invalid container ID for systemd scope")
	}
	if limits.memoryBytes < 16<<20 || limits.cpuMillis < 10 {
		return command{}, errors.New("invalid resource limits for systemd scope")
	}
	outerPIDs, err := outerPIDLimit(limits.pids)
	if err != nil {
		return command{}, err
	}
	cpuQuota := strconv.FormatFloat(float64(limits.cpuMillis)/10, 'f', 1, 64) + "%"
	arguments := []string{
		"--user",
		"--scope",
		"--quiet",
		"--unit=" + containerID,
		"--property=MemoryAccounting=yes",
		"--property=CPUAccounting=yes",
		"--property=TasksAccounting=yes",
		"--property=IOAccounting=yes",
		"--property=MemoryMax=" + strconv.FormatInt(limits.memoryBytes, 10),
		"--property=MemorySwapMax=0",
		"--property=CPUQuota=" + cpuQuota,
		"--property=TasksMax=" + strconv.FormatInt(outerPIDs, 10),
		"--",
		invocation.Path,
	}
	arguments = append(arguments, invocation.Args...)
	return command{
		Path:   p.config.SystemdRunPath,
		Args:   arguments,
		Stdout: invocation.Stdout,
		Stderr: invocation.Stderr,
	}, nil
}

func systemdCgroupPath(root, containerID string) string {
	return root + "/" + containerID + ".scope"
}
