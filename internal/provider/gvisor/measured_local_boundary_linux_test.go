//go:build linux

package gvisor

import (
	"net/netip"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestMeasuredLocalBoundaryRefusesWidening(t *testing.T) {
	job := measuredSpecJob(t)
	workload := np.MappedIdentity{UID: 40000, GID: 40000, OverflowUID: 40001, OverflowGID: 40001}
	router := np.MappedIdentity{UID: 40002, GID: 40002, OverflowUID: 40003, OverflowGID: 40003}
	maximum := proto.Clone(job.EffectivePolicy).(*p.EffectivePolicy)
	sensitive := []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}
	b, err := newMeasuredLocalBoundary(maximum, workload, router, sensitive, time.Minute)
	if err != nil || b.check(job, workload, router) != nil {
		t.Fatal("valid boundary refused", err)
	}
	maximum.Resources.MemoryBytes++
	maximum.NetworkV2.MaximumConnections++
	sensitive[0] = netip.MustParsePrefix("1.1.1.1/32")
	if b.maximum.Resources.MemoryBytes != job.EffectivePolicy.Resources.MemoryBytes || b.dns.SensitiveNetworks[0].String() != "93.184.216.0/24" {
		t.Fatal("mutable provisioning boundary")
	}
	for name, mutate := range map[string]func(*p.EffectivePolicy){
		"cpu":       func(x *p.EffectivePolicy) { x.Resources.CpuMillis++ },
		"memory":    func(x *p.EffectivePolicy) { x.Resources.MemoryBytes++ },
		"disk":      func(x *p.EffectivePolicy) { x.Resources.DiskBytes++ },
		"processes": func(x *p.EffectivePolicy) { x.Resources.ProcessCount++ },
		"preparation": func(x *p.EffectivePolicy) {
			x.PreparationTimeout = durationpb.New(x.PreparationTimeout.AsDuration() + time.Millisecond)
		},
		"execution": func(x *p.EffectivePolicy) {
			x.ExecutionTimeout = durationpb.New(x.ExecutionTimeout.AsDuration() + time.Millisecond)
		},
		"shutdown": func(x *p.EffectivePolicy) {
			x.GracefulShutdownTimeout = durationpb.New(x.GracefulShutdownTimeout.AsDuration() + time.Millisecond)
		},
		"connections": func(x *p.EffectivePolicy) { x.NetworkV2.MaximumConnections++ },
		"bytes":       func(x *p.EffectivePolicy) { x.NetworkV2.MaximumBytesPerSecond++ },
		"tuple":       func(x *p.EffectivePolicy) { x.NetworkV2.Permissions[0].Port++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.Clone(job).(*p.JobSpecification)
			mutate(changed.EffectivePolicy)
			hash, err := np.EffectivePolicyV2SHA256(changed.EffectivePolicy)
			if err != nil {
				t.Fatal(err)
			}
			changed.Hashes.Policy.Value = hash[:]
			if b.check(changed, workload, router) == nil {
				t.Fatal("widened frozen policy admitted")
			}
		})
	}
	if b.check(job, router, workload) == nil {
		t.Fatal("foreign identities admitted")
	}
	if b.check(job, workload, router) != nil {
		t.Fatal("refusal changed immutable boundary")
	}
}

func TestMeasuredLocalBoundaryRejectsInvalidProvisioning(t *testing.T) {
	job := measuredSpecJob(t)
	w := np.MappedIdentity{UID: 40000, GID: 40000, OverflowUID: 40001, OverflowGID: 40001}
	r := np.MappedIdentity{UID: 40002, GID: 40002, OverflowUID: 40003, OverflowGID: 40003}
	sensitive := []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}
	for _, maximum := range []*p.EffectivePolicy{nil, {}, proto.Clone(job.EffectivePolicy).(*p.EffectivePolicy)} {
		if maximum != nil && maximum.Resources != nil {
			maximum.Resources.MemoryBytes = ^uint64(0)
		}
		if b, err := newMeasuredLocalBoundary(maximum, w, r, sensitive, time.Minute); b != nil || err == nil {
			t.Fatal("invalid maximum admitted")
		}
	}
	if b, err := newMeasuredLocalBoundary(job.EffectivePolicy, w, w, sensitive, time.Minute); b != nil || err == nil {
		t.Fatal("overlapping identities admitted")
	}
	if b, err := newMeasuredLocalBoundary(job.EffectivePolicy, w, r, nil, time.Minute); b != nil || err == nil {
		t.Fatal("missing sensitive inventory admitted")
	}
	if b, err := newMeasuredLocalBoundary(job.EffectivePolicy, w, r, sensitive, 0); b != nil || err == nil {
		t.Fatal("unbounded TTL admitted")
	}
	var absent *measuredLocalBoundary
	if absent.check(job, w, r) == nil {
		t.Fatal("missing boundary admitted")
	}
}
