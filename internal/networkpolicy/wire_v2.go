package networkpolicy

import (
	"bytes"
	"crypto/sha256"
	"net/netip"
	"strings"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
)

// LocalV2Boundary is trusted operator configuration, never workload input. Its
// maximum must be the same immutable local maximum advertised for this job.
// Resolver selection, TTL and sensitive inventory do not come from the grant.
type LocalV2Boundary struct {
	Maximum           *runnerv1.NetworkPolicyV2
	SensitiveNetworks []netip.Prefix
	MaximumTTL        time.Duration
}

// NewV2Binder validates an already authenticated complete grant and translates
// whole tuples without narrowing or repairing it. This does not authenticate a
// gateway, admit an offer, install rules, or grant permission to advertise v2.
// The caller must separately bind the job, lease and immutable local maximum.
// Existing production offer/Paper admission remains disabled for every v2 job.
func NewV2Binder(job string, raw []byte, expected [sha256.Size]byte, local LocalV2Boundary, resolver Exchange) (*Binder, error) {
	if len(raw) == 0 || len(raw) > 65536 || sha256.Sum256(raw) != expected || ValidateWireV2(local.Maximum) != nil {
		return nil, ErrPolicy
	}
	var effective runnerv1.EffectivePolicy
	if proto.Unmarshal(raw, &effective) != nil || !closedWireV2(effective.ProtoReflect()) || effective.Network != nil || ValidateWireV2(effective.NetworkV2) != nil {
		return nil, ErrPolicy
	}
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&effective)
	if err != nil || !bytes.Equal(raw, canonical) || !WithinLocalMaximumV2(effective.NetworkV2, local.Maximum) {
		return nil, ErrPolicy
	}
	if effective.Sandbox == runnerv1.SandboxKind_SANDBOX_KIND_UNSPECIFIED || effective.Requirement == runnerv1.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_UNSPECIFIED || effective.Resources == nil || effective.Resources.CpuMillis == 0 || effective.Resources.MemoryBytes == 0 || effective.Resources.DiskBytes == 0 || effective.Resources.ProcessCount == 0 {
		return nil, ErrPolicy
	}
	for _, d := range []*durationpb.Duration{effective.PreparationTimeout, effective.ExecutionTimeout, effective.GracefulShutdownTimeout} {
		if d == nil || d.CheckValid() != nil || d.Seconds < 0 || d.Nanos < 0 || (d.Seconds == 0 && d.Nanos == 0) {
			return nil, ErrPolicy
		}
	}
	p := effective.NetworkV2
	options := Options{JobID: job, Mode: "none", SensitiveNetworks: local.SensitiveNetworks}
	if p.Mode != runnerv1.NetworkMode_NETWORK_MODE_NONE {
		options.Mode = "restricted"
		if p.Mode == runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST {
			options.Mode = "allowlist"
		}
		options.MaximumTTL = local.MaximumTTL
		options.Limits = Limits{Connections: uint64(p.MaximumConnections), BytesPerSecond: uint64(p.MaximumBytesPerSecond)}
		for _, permission := range p.Permissions {
			transport := "tcp"
			if permission.Transport == runnerv1.NetworkTransportV2_NETWORK_TRANSPORT_V2_UDP {
				transport = "udp"
			}
			options.Permissions = append(options.Permissions, Permission{Hostname: permission.Hostname, Port: uint16(permission.Port), Protocol: transport})
		}
	}
	return New(options, resolver)
}

// ValidateWireV2 accepts only the released canonical bounded representation.
// It neither sorts malformed tuples nor collapses independent grants into sets.
func ValidateWireV2(p *runnerv1.NetworkPolicyV2) error {
	if p == nil || len(p.ProtoReflect().GetUnknown()) != 0 || len(p.Permissions) > 128 {
		return ErrPolicy
	}
	if p.Mode == runnerv1.NetworkMode_NETWORK_MODE_NONE {
		if len(p.Permissions) != 0 || p.MaximumConnections != 0 || p.MaximumBytesPerSecond != 0 {
			return ErrPolicy
		}
		return nil
	}
	if (p.Mode != runnerv1.NetworkMode_NETWORK_MODE_RESTRICTED && p.Mode != runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST) || len(p.Permissions) == 0 || p.MaximumConnections == 0 || p.MaximumBytesPerSecond == 0 {
		return ErrPolicy
	}
	for i, permission := range p.Permissions {
		if permission == nil || len(permission.ProtoReflect().GetUnknown()) != 0 || !hostname(permission.Hostname) || permission.Port > 65535 || blockedPort(uint16(permission.Port)) || (permission.Transport != runnerv1.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP && permission.Transport != runnerv1.NetworkTransportV2_NETWORK_TRANSPORT_V2_UDP) {
			return ErrPolicy
		}
		if i > 0 && compareWirePermissionV2(p.Permissions[i-1], permission) >= 0 {
			return ErrPolicy
		}
	}
	return nil
}

func compareWirePermissionV2(a, b *runnerv1.NetworkPermissionV2) int {
	if c := strings.Compare(a.Hostname, b.Hostname); c != 0 {
		return c
	}
	if a.Port < b.Port {
		return -1
	}
	if a.Port > b.Port {
		return 1
	}
	if a.Transport < b.Transport {
		return -1
	}
	if a.Transport > b.Transport {
		return 1
	}
	return 0
}

// WithinLocalMaximumV2 refuses widening, including cross-product tuples and
// malformed maxima absorbed by none. It never silently narrows a frozen grant.
func WithinLocalMaximumV2(effective, maximum *runnerv1.NetworkPolicyV2) bool {
	if ValidateWireV2(effective) != nil || ValidateWireV2(maximum) != nil {
		return false
	}
	if effective.Mode == runnerv1.NetworkMode_NETWORK_MODE_NONE {
		return true
	}
	if maximum.Mode == runnerv1.NetworkMode_NETWORK_MODE_NONE || effective.MaximumConnections > maximum.MaximumConnections || effective.MaximumBytesPerSecond > maximum.MaximumBytesPerSecond {
		return false
	}
	i := 0
	for _, permission := range effective.Permissions {
		for i < len(maximum.Permissions) && compareWirePermissionV2(maximum.Permissions[i], permission) < 0 {
			i++
		}
		if i == len(maximum.Permissions) || compareWirePermissionV2(maximum.Permissions[i], permission) != 0 {
			return false
		}
	}
	return true
}

func closedWireV2(message protoreflect.Message) bool {
	if !message.IsValid() || len(message.GetUnknown()) != 0 {
		return false
	}
	valid := true
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsMap() {
			valid = false
			return false
		}
		check := func(v protoreflect.Value) bool {
			if field.Kind() == protoreflect.EnumKind {
				return field.Enum().Values().ByNumber(v.Enum()) != nil
			}
			if field.Kind() == protoreflect.MessageKind {
				return closedWireV2(v.Message())
			}
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				if !check(list.Get(i)) {
					valid = false
					return false
				}
			}
		} else {
			valid = check(value)
		}
		return valid
	})
	return valid
}
