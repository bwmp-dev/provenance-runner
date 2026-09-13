package networkpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func releasedEffectiveV2(t *testing.T) (*runnerv1.EffectivePolicy, []byte) {
	t.Helper()
	data, err := os.ReadFile("testdata/released-v2-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ EffectivePolicyWireHex string }
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(v.EffectivePolicyWireHex)
	if err != nil {
		t.Fatal(err)
	}
	p := new(runnerv1.EffectivePolicy)
	if err := proto.Unmarshal(raw, p); err != nil {
		t.Fatal(err)
	}
	return p, raw
}

func TestV2BinderReleasedIdentityWholeTuplesAndCopiedLocalBoundary(t *testing.T) {
	p, raw := releasedEffectiveV2(t)
	local := LocalV2Boundary{Maximum: proto.Clone(p.NetworkV2).(*runnerv1.NetworkPolicyV2), SensitiveNetworks: prefixes("93.184.216.0/24"), MaximumTTL: time.Minute}
	b, err := NewV2Binder(options().JobID, raw, sha256.Sum256(raw), local, responder(nil))
	if err != nil {
		t.Fatal(err)
	}
	// Subsequent caller mutation cannot change the accepted grant or inventory.
	raw[0] ^= 1
	local.Maximum.Permissions[0].Hostname = "changed.example"
	local.SensitiveNetworks[0] = netip.MustParsePrefix("0.0.0.0/0")
	for _, expected := range []Permission{{"a.example", 443, "tcp"}, {"b.example", 8443, "udp"}} {
		binding, err := b.Resolve(context.Background(), expected.Hostname)
		if err != nil || !reflect.DeepEqual(binding.Permissions(), []Permission{expected}) || binding.Limits() != (Limits{8, 65536}) {
			t.Fatal("tuple or budget changed", err)
		}
	}
	if _, err := b.Resolve(context.Background(), "changed.example"); !errors.Is(err, ErrDenied) {
		t.Fatal("caller mutation granted DNS", err)
	}
}

func TestV2BinderNoneDoesNotResolveAndMalformedMaximumCannotBeAbsorbed(t *testing.T) {
	p, _ := releasedEffectiveV2(t)
	maximum := p.NetworkV2
	p.NetworkV2 = &runnerv1.NetworkPolicyV2{Mode: runnerv1.NetworkMode_NETWORK_MODE_NONE}
	raw, _ := proto.Marshal(p)
	local := LocalV2Boundary{Maximum: maximum, SensitiveNetworks: options().SensitiveNetworks, MaximumTTL: time.Minute}
	b, err := NewV2Binder(options().JobID, raw, sha256.Sum256(raw), local, exchangeFunc(func(context.Context, []byte) ([]byte, error) { t.Fatal("none made a DNS query"); return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Resolve(context.Background(), "a.example"); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	local.Maximum.MaximumConnections = 0
	if _, err := NewV2Binder(options().JobID, raw, sha256.Sum256(raw), local, responder(nil)); !errors.Is(err, ErrPolicy) {
		t.Fatal("none absorbed invalid authority", err)
	}
}

func TestV2BinderRefusesMalformedFullIdentityBeforeDNS(t *testing.T) {
	for name, mutate := range map[string]func(*runnerv1.EffectivePolicy){
		"missing network": func(p *runnerv1.EffectivePolicy) { p.NetworkV2 = nil },
		"mixed legacy": func(p *runnerv1.EffectivePolicy) {
			p.Network = &runnerv1.NetworkPolicy{Mode: runnerv1.NetworkMode_NETWORK_MODE_NONE}
		},
		"missing resources":   func(p *runnerv1.EffectivePolicy) { p.Resources = nil },
		"zero CPU":            func(p *runnerv1.EffectivePolicy) { p.Resources.CpuMillis = 0 },
		"zero memory":         func(p *runnerv1.EffectivePolicy) { p.Resources.MemoryBytes = 0 },
		"zero disk":           func(p *runnerv1.EffectivePolicy) { p.Resources.DiskBytes = 0 },
		"zero processes":      func(p *runnerv1.EffectivePolicy) { p.Resources.ProcessCount = 0 },
		"missing sandbox":     func(p *runnerv1.EffectivePolicy) { p.Sandbox = 0 },
		"unknown sandbox":     func(p *runnerv1.EffectivePolicy) { p.Sandbox = 999 },
		"missing requirement": func(p *runnerv1.EffectivePolicy) { p.Requirement = 0 },
		"unknown requirement": func(p *runnerv1.EffectivePolicy) { p.Requirement = 999 },
		"missing timeout":     func(p *runnerv1.EffectivePolicy) { p.PreparationTimeout = nil },
		"negative timeout":    func(p *runnerv1.EffectivePolicy) { p.ExecutionTimeout.Seconds = -1 },
		"zero timeout":        func(p *runnerv1.EffectivePolicy) { p.GracefulShutdownTimeout.Seconds = 0 },
		"invalid nanos":       func(p *runnerv1.EffectivePolicy) { p.ExecutionTimeout.Nanos = 1000000000 },
		"unknown root":        func(p *runnerv1.EffectivePolicy) { p.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 1}) },
		"unknown nested":      func(p *runnerv1.EffectivePolicy) { p.Resources.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 1}) },
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := releasedEffectiveV2(t)
			local := LocalV2Boundary{Maximum: proto.Clone(p.NetworkV2).(*runnerv1.NetworkPolicyV2), SensitiveNetworks: options().SensitiveNetworks, MaximumTTL: time.Minute}
			mutate(p)
			raw, err := proto.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewV2Binder(options().JobID, raw, sha256.Sum256(raw), local, responder(nil)); !errors.Is(err, ErrPolicy) {
				t.Fatal("malformed policy accepted", err)
			}
		})
	}
	p, raw := releasedEffectiveV2(t)
	local := LocalV2Boundary{Maximum: p.NetworkV2, SensitiveNetworks: options().SensitiveNetworks, MaximumTTL: time.Minute}
	if _, err := NewV2Binder(options().JobID, raw, [32]byte{}, local, responder(nil)); !errors.Is(err, ErrPolicy) {
		t.Fatal("wrong identity accepted", err)
	}
	for _, wire := range [][]byte{nil, make([]byte, 65537), append(append([]byte(nil), raw...), raw[:2]...)} {
		if _, err := NewV2Binder(options().JobID, wire, sha256.Sum256(wire), local, responder(nil)); !errors.Is(err, ErrPolicy) {
			t.Fatal("noncanonical or unbounded bytes accepted", err)
		}
	}
}

func TestWireV2CanonicalRefusals(t *testing.T) {
	for name, mutate := range map[string]func(*runnerv1.NetworkPolicyV2){
		"unspecified":          func(p *runnerv1.NetworkPolicyV2) { p.Mode = 0 },
		"unrestricted":         func(p *runnerv1.NetworkPolicyV2) { p.Mode = 4 },
		"unknown":              func(p *runnerv1.NetworkPolicyV2) { p.Mode = 999 },
		"none grants":          func(p *runnerv1.NetworkPolicyV2) { p.Mode = 1 },
		"empty":                func(p *runnerv1.NetworkPolicyV2) { p.Permissions = nil },
		"too many":             func(p *runnerv1.NetworkPolicyV2) { p.Permissions = make([]*runnerv1.NetworkPermissionV2, 129) },
		"nil tuple":            func(p *runnerv1.NetworkPolicyV2) { p.Permissions[0] = nil },
		"zero connections":     func(p *runnerv1.NetworkPolicyV2) { p.MaximumConnections = 0 },
		"zero rate":            func(p *runnerv1.NetworkPolicyV2) { p.MaximumBytesPerSecond = 0 },
		"unknown policy field": func(p *runnerv1.NetworkPolicyV2) { p.ProtoReflect().SetUnknown([]byte{0xf8, 7, 1}) },
		"unknown tuple field":  func(p *runnerv1.NetworkPolicyV2) { p.Permissions[0].ProtoReflect().SetUnknown([]byte{0xf8, 7, 1}) },
		"duplicate": func(p *runnerv1.NetworkPolicyV2) {
			p.Permissions[1] = proto.Clone(p.Permissions[0]).(*runnerv1.NetworkPermissionV2)
		},
		"unsorted": func(p *runnerv1.NetworkPolicyV2) {
			p.Permissions[0], p.Permissions[1] = p.Permissions[1], p.Permissions[0]
		},
		"bad transport":    func(p *runnerv1.NetworkPolicyV2) { p.Permissions[0].Transport = 3 },
		"absent transport": func(p *runnerv1.NetworkPolicyV2) { p.Permissions[0].Transport = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := releasedEffectiveV2(t)
			mutate(p.NetworkV2)
			if ValidateWireV2(p.NetworkV2) == nil {
				t.Fatal("invalid wire accepted")
			}
		})
	}
	for _, port := range []uint32{0, 25, 53, 465, 587, 853, 65536, 0xffffffff} {
		p, _ := releasedEffectiveV2(t)
		p.NetworkV2.Permissions[0].Port = port
		if ValidateWireV2(p.NetworkV2) == nil {
			t.Fatal("invalid port", port)
		}
	}
	for _, host := range []string{"A.example", "a.example.", "localhost", "127.0.0.1", "0x7f.0.0.1", "0xffffffffffffffffffff.0.1", "::1", "a..example", "*.example", "-a.example", "a_.example", strings.Repeat("a", 64) + ".example"} {
		p, _ := releasedEffectiveV2(t)
		p.NetworkV2.Permissions[0].Hostname = host
		if ValidateWireV2(p.NetworkV2) == nil {
			t.Fatal("invalid hostname", host)
		}
	}
}

func TestWireV2MaximumRefusesWideningAndCrossProduct(t *testing.T) {
	p, _ := releasedEffectiveV2(t)
	maximum := p.NetworkV2
	for _, mutate := range []func(*runnerv1.NetworkPolicyV2){
		func(p *runnerv1.NetworkPolicyV2) { p.MaximumConnections++ },
		func(p *runnerv1.NetworkPolicyV2) { p.MaximumBytesPerSecond++ },
		func(p *runnerv1.NetworkPolicyV2) { p.Permissions[0].Port = 8443 },
		func(p *runnerv1.NetworkPolicyV2) { p.Permissions[0].Transport = 2 },
		func(p *runnerv1.NetworkPolicyV2) { p.Permissions[1].Hostname = "z.example" },
	} {
		effective := proto.Clone(maximum).(*runnerv1.NetworkPolicyV2)
		mutate(effective)
		if WithinLocalMaximumV2(effective, maximum) {
			t.Fatal("widened grant accepted")
		}
	}
	effective := proto.Clone(maximum).(*runnerv1.NetworkPolicyV2)
	effective.Permissions = effective.Permissions[:1]
	effective.MaximumConnections = 1
	if !WithinLocalMaximumV2(effective, maximum) {
		t.Fatal("strict subset refused")
	}
}
