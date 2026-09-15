//go:build linux

package gvisor

import (
	"errors"
	"path/filepath"
	"strings"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

var errMeasuredNetworkSpec = errors.New("measured_network_spec_unavailable")

// measuredGuestCommand describes guest execution only. It deliberately has no
// host mounts, identities, resource overrides, runtime flags or namespace paths.
type measuredGuestCommand struct {
	Command     string
	Arguments   []string
	Environment map[string]string
}

// buildMeasuredNetworkSpec is a pure trusted-controller constructor, not an
// admission check or an RPC. The controller must provision and retain the exact
// private bundle, regular-file-only read-only inputs and measured image before
// launch; this function never claims that a pathname proves those objects.
func buildMeasuredNetworkSpec(job *p.JobSpecification, command measuredGuestCommand, privateRoot string) (ociSpec, error) {
	if job == nil {
		return ociSpec{}, errMeasuredNetworkSpec
	}
	job = proto.Clone(job).(*p.JobSpecification)
	if _, err := np.NewAuthority(job); err != nil || job.EffectivePolicy.Sandbox != p.SandboxKind_SANDBOX_KIND_GVISOR || job.EffectivePolicy.NetworkV2.Mode == p.NetworkMode_NETWORK_MODE_NONE {
		return ociSpec{}, errMeasuredNetworkSpec
	}
	if !filepath.IsAbs(privateRoot) || filepath.Clean(privateRoot) != privateRoot || filepath.Base(privateRoot) != ".measured-root" || filepath.Base(filepath.Dir(privateRoot)) != job.Lease.JobId || len(privateRoot) > 4096 || strings.ContainsAny(privateRoot, "\x00\r\n") {
		return ociSpec{}, errMeasuredNetworkSpec
	}
	if len(command.Arguments) > 256 || len(command.Environment) > 128 {
		return ociSpec{}, errMeasuredNetworkSpec
	}
	bytes := len(command.Command)
	for _, arg := range command.Arguments {
		if len(arg) > 65536 {
			return ociSpec{}, errMeasuredNetworkSpec
		}
		bytes += len(arg)
	}
	for key, value := range command.Environment {
		if len(key) > 128 || len(value) > 65536 {
			return ociSpec{}, errMeasuredNetworkSpec
		}
		bytes += len(key) + len(value)
	}
	if bytes > 65536 {
		return ociSpec{}, errMeasuredNetworkSpec
	}
	limits := job.EffectivePolicy.Resources
	config := configuration{Command: command.Command, Arguments: command.Arguments, Environment: command.Environment,
		MemoryBytes: int64(limits.MemoryBytes), CPUMillis: int64(limits.CpuMillis), PIDs: int64(limits.ProcessCount), DiskBytes: int64(limits.DiskBytes)}
	if validateGuestConfiguration(config) != nil {
		return ociSpec{}, errMeasuredNetworkSpec
	}
	spec, err := buildSpec(config, privateRoot, filepath.Join(filepath.Dir(privateRoot), "inputs"), job.Lease.JobId, nil, nil)
	if err != nil {
		return ociSpec{}, errMeasuredNetworkSpec
	}
	// The outer owner places the entire runtime in its retained cgroup at birth.
	// runsc must not create or select another cgroup by a caller-provided path.
	spec.Linux.CgroupsPath = ""
	spec.Mounts = append(spec.Mounts, ociMount{Destination: "/etc/resolv.conf", Type: "bind", Source: filepath.Join(filepath.Dir(privateRoot), "resolv.conf"), Options: []string{"bind", "ro", "nosuid", "nodev", "noexec"}})
	for i := range spec.Linux.Namespaces {
		if spec.Linux.Namespaces[i].Type == "network" {
			// This is the already-wired child's private namespace, never the
			// controller or host namespace; the closed handoff proves separation.
			spec.Linux.Namespaces[i].Path = "/proc/self/ns/net"
		}
	}
	return spec, nil
}
