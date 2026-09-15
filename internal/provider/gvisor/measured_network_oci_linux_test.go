//go:build linux

package gvisor

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func measuredSpecJob(t *testing.T) *p.JobSpecification {
	t.Helper()
	id := func(prefix string) string { return prefix + "0000000-0000-4000-8000-000000000001" }
	job := &p.JobSpecification{
		Lease:   &p.LeaseIdentity{JobId: id("1"), LeaseId: id("2"), ExecutionId: id("3"), ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))},
		Attempt: &p.AttemptIdentity{AttemptId: id("4"), ReleaseCandidateId: id("5"), MatrixEntryId: id("6"), AttemptNumber: 1},
		EffectivePolicy: &p.EffectivePolicy{Sandbox: p.SandboxKind_SANDBOX_KIND_GVISOR, Requirement: p.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED,
			Resources:          &p.ResourceLimits{CpuMillis: 2000, MemoryBytes: 1 << 30, DiskBytes: 2 << 20, ProcessCount: 256},
			PreparationTimeout: durationpb.New(time.Minute), ExecutionTimeout: durationpb.New(time.Minute), GracefulShutdownTimeout: durationpb.New(time.Second),
			NetworkV2: &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_ALLOWLIST, MaximumConnections: 16, MaximumBytesPerSecond: 65536,
				Permissions: []*p.NetworkPermissionV2{{Hostname: "fixture.example.com", Port: 8080, Transport: p.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP}}}},
	}
	digest, err := np.EffectivePolicyV2SHA256(job.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	job.Hashes = &p.JobHashes{Policy: &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}}
	return job
}

func TestMeasuredNetworkSpecKeepsClosedConfinement(t *testing.T) {
	job := measuredSpecJob(t)
	root := filepath.Join("/owned", job.Lease.JobId, ".measured-root")
	command := measuredGuestCommand{Command: "/smoke", Arguments: []string{"probe"}, Environment: map[string]string{"FIXTURE": "yes"}}
	spec, err := buildMeasuredNetworkSpec(job, command, root)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Root.Readonly || spec.Root.Path != root || spec.Linux.CgroupsPath != "" || spec.Process.User.UID != 65532 || spec.Process.User.GID != 65532 || spec.Process.User.Umask != 077 || len(spec.Process.User.AdditionalGids) != 0 || !spec.Process.NoNewPrivileges || spec.Process.Cwd != "/workspace" {
		t.Fatal("closed runtime boundary changed")
	}
	for _, caps := range [][]string{spec.Process.Capabilities.Bounding, spec.Process.Capabilities.Effective, spec.Process.Capabilities.Inheritable, spec.Process.Capabilities.Permitted, spec.Process.Capabilities.Ambient} {
		if len(caps) != 0 {
			t.Fatal("guest capability granted")
		}
	}
	if spec.Linux.Resources.Memory.Limit != 1<<30 || spec.Linux.Resources.CPU.Quota != 200000 || spec.Linux.Resources.PIDs.Limit != 273 {
		t.Fatal("frozen resources not derived")
	}
	if len(spec.Mounts) != 7 {
		t.Fatal("unexpected host mount")
	}
	for _, mount := range spec.Mounts {
		switch mount.Destination {
		case "/etc/resolv.conf":
			if mount.Type != "bind" || mount.Source != filepath.Join(filepath.Dir(root), "resolv.conf") || !slices.Equal(mount.Options, []string{"bind", "ro", "nosuid", "nodev", "noexec"}) {
				t.Fatal("resolver escaped fixed protected binding")
			}
		case "/workspace", "/tmp":
			if mount.Type != "tmpfs" || !slices.Contains(mount.Options, "size=1048576") || !slices.Contains(mount.Options, "uid=65532") || !slices.Contains(mount.Options, "nosuid") || !slices.Contains(mount.Options, "nodev") {
				t.Fatal("unbounded writable storage")
			}
		case "/inputs":
			if mount.Source != filepath.Join(filepath.Dir(root), "inputs") || !slices.Contains(mount.Options, "ro") || !slices.Contains(mount.Options, "noexec") {
				t.Fatal("inputs escaped fixed read-only binding")
			}
		}
	}
	for _, ns := range spec.Linux.Namespaces {
		want := ""
		if ns.Type == "network" {
			want = "/proc/self/ns/net"
		}
		if ns.Path != want {
			t.Fatal("ambient namespace selected")
		}
	}
	command.Arguments[0], command.Environment["FIXTURE"] = "changed", "changed"
	job.EffectivePolicy.Resources.MemoryBytes = 1
	if spec.Process.Args[1] != "probe" || !slices.Contains(spec.Process.Env, "FIXTURE=yes") || spec.Linux.Resources.Memory.Limit != 1<<30 {
		t.Fatal("caller mutation changed constructed spec")
	}
}

func TestMeasuredNetworkSpecRejectsAmbiguousInputs(t *testing.T) {
	job := measuredSpecJob(t)
	root := filepath.Join("/owned", job.Lease.JobId, ".measured-root")
	for _, command := range []measuredGuestCommand{{}, {Command: "relative"}, {Command: "/smoke", Arguments: []string{"bad\x00"}}, {Command: "/smoke", Environment: map[string]string{"bad=key": "value"}}, {Command: "/smoke", Arguments: make([]string, 257)}, {Command: "/smoke", Arguments: []string{strings.Repeat("x", 65537)}}} {
		if _, err := buildMeasuredNetworkSpec(job, command, root); err == nil {
			t.Fatal("invalid guest command accepted")
		}
	}
	command := measuredGuestCommand{Command: "/smoke"}
	for _, path := range []string{"", "/", "/owned/foreign/.measured-root", root + "/..", root + "\n"} {
		if _, err := buildMeasuredNetworkSpec(job, command, path); err == nil {
			t.Fatal("foreign bundle accepted")
		}
	}
	for _, bad := range []*p.JobSpecification{nil, {}, proto.Clone(job).(*p.JobSpecification)} {
		if bad != nil && bad.EffectivePolicy != nil {
			bad.EffectivePolicy.Resources.MemoryBytes++
		}
		if _, err := buildMeasuredNetworkSpec(bad, command, root); err == nil {
			t.Fatal("unfrozen job accepted")
		}
	}
}

func TestMeasuredNetworkSpecDoesNotRelaxLegacyAdmission(t *testing.T) {
	job := measuredSpecJob(t)
	root := filepath.Join("/owned", job.Lease.JobId, ".measured-root")
	for _, mutate := range []func(*p.JobSpecification){
		func(job *p.JobSpecification) { job.EffectivePolicy.Resources.DiskBytes = 1 },
		func(job *p.JobSpecification) { job.EffectivePolicy.Resources.MemoryBytes = ^uint64(0) },
		func(job *p.JobSpecification) {
			job.EffectivePolicy.NetworkV2 = &p.NetworkPolicyV2{Mode: p.NetworkMode_NETWORK_MODE_NONE}
		},
	} {
		bad := proto.Clone(job).(*p.JobSpecification)
		mutate(bad)
		if digest, err := np.EffectivePolicyV2SHA256(bad.EffectivePolicy); err == nil {
			bad.Hashes.Policy.Value = digest[:]
		}
		if _, err := buildMeasuredNetworkSpec(bad, measuredGuestCommand{Command: "/smoke"}, root); err == nil {
			t.Fatal("unsupported resource or network profile accepted")
		}
	}
	if validateGuestConfiguration(configuration{Command: "/smoke", Network: "sandbox", MemoryBytes: 1 << 30, CPUMillis: 2000, PIDs: 256, DiskBytes: 2 << 20}) == nil {
		t.Fatal("requested label bypassed network-none provider")
	}
}
