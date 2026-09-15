//go:build linux

package gvisor

import (
	"net/netip"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// measuredLocalBoundary is immutable trusted provisioning state. Jobs cannot
// choose host identities or widen network, resource or phase-time ceilings.
// It is admission policy, not an exclusive identity or capacity reservation.
type measuredLocalBoundary struct {
	maximum          *p.EffectivePolicy
	workload, router np.MappedIdentity
	dns              np.LocalV2Boundary
}

func validMeasuredEffective(policy *p.EffectivePolicy) bool {
	if _, err := np.EffectivePolicyV2SHA256(policy); err != nil || policy.Sandbox != p.SandboxKind_SANDBOX_KIND_GVISOR || policy.Requirement != p.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED || policy.NetworkV2.Mode == p.NetworkMode_NETWORK_MODE_NONE {
		return false
	}
	r := policy.Resources
	if validateGuestConfiguration(configuration{Command: "/validation-only", MemoryBytes: int64(r.MemoryBytes), CPUMillis: int64(r.CpuMillis), PIDs: int64(r.ProcessCount), DiskBytes: int64(r.DiskBytes)}) != nil {
		return false
	}
	for _, d := range []*durationpb.Duration{policy.PreparationTimeout, policy.ExecutionTimeout, policy.GracefulShutdownTimeout} {
		value := d.AsDuration()
		if value <= 0 || value > localjob.MaximumTimeout || value%time.Millisecond != 0 {
			return false
		}
	}
	return true
}

func newMeasuredLocalBoundary(maximum *p.EffectivePolicy, workload, router np.MappedIdentity, sensitive []netip.Prefix, ttl time.Duration) (*measuredLocalBoundary, error) {
	if !validMeasuredEffective(maximum) || !validPreparationMapping(workload) || !validPreparationMapping(router) || len(sensitive) == 0 || len(sensitive) > 256 || ttl < time.Second || ttl > 5*time.Minute {
		return nil, errMeasuredSession
	}
	for _, prefix := range sensitive {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return nil, errMeasuredSession
		}
	}
	for _, id := range []uint32{workload.UID, workload.OverflowUID} {
		if id == router.UID || id == router.OverflowUID {
			return nil, errMeasuredSession
		}
	}
	for _, id := range []uint32{workload.GID, workload.OverflowGID} {
		if id == router.GID || id == router.OverflowGID {
			return nil, errMeasuredSession
		}
	}
	maximum = proto.Clone(maximum).(*p.EffectivePolicy)
	return &measuredLocalBoundary{maximum: maximum, workload: workload, router: router,
		dns: np.LocalV2Boundary{Maximum: maximum.NetworkV2, SensitiveNetworks: append([]netip.Prefix(nil), sensitive...), MaximumTTL: ttl}}, nil
}

func (b *measuredLocalBoundary) check(job *p.JobSpecification, workload, router np.MappedIdentity) error {
	if b == nil || b.maximum == nil || job == nil || workload != b.workload || router != b.router || !validMeasuredEffective(job.EffectivePolicy) {
		return errMeasuredSession
	}
	if _, err := np.NewAuthority(job); err != nil {
		return errMeasuredSession
	}
	policy, maximum := job.EffectivePolicy, b.maximum
	r, m := policy.Resources, maximum.Resources
	if !np.WithinLocalMaximumV2(policy.NetworkV2, maximum.NetworkV2) || r.CpuMillis > m.CpuMillis || r.MemoryBytes > m.MemoryBytes || r.DiskBytes > m.DiskBytes || r.ProcessCount > m.ProcessCount {
		return errMeasuredSession
	}
	for _, pair := range [][2]*durationpb.Duration{{policy.PreparationTimeout, maximum.PreparationTimeout}, {policy.ExecutionTimeout, maximum.ExecutionTimeout}, {policy.GracefulShutdownTimeout, maximum.GracefulShutdownTimeout}} {
		if pair[0].AsDuration() > pair[1].AsDuration() {
			return errMeasuredSession
		}
	}
	return nil
}
