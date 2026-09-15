//go:build linux

package measuredservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"google.golang.org/protobuf/encoding/protojson"
)

func fixtureDaemonConfig(t *testing.T) DaemonConfig {
	t.Helper()
	source, _, job := serviceFixtureJob(t, []byte("java"), []byte("prepared"))
	policy, err := protojson.Marshal(job.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	return DaemonConfig{Version: 1, WorkerUID: 65532, WorkerGID: 65532,
		SocketDirectory: "/run/provenance-measured", CgroupParent: "/sys/fs/cgroup/measured-jobs",
		CgroupState: "/var/lib/provenance-measured/cgroups", BundleRoot: "/var/lib/provenance-measured/work",
		BundleState: "/var/lib/provenance-measured/bundles", UplinkState: "/var/lib/provenance-measured/uplinks",
		SandboxPath: "/opt/provenance/runsc", RootPath: "/opt/provenance/root", ImagePath: "/opt/provenance/root.squashfs", LoopPath: "/dev/loop42",
		RunnerSHA256: strings.Repeat("1", 64), SandboxSHA256: strings.Repeat("2", 64), RootFSSHA256: strings.Repeat("3", 64),
		IP: DaemonTool{"/usr/bin/ip", strings.Repeat("4", 64)}, NFT: DaemonTool{"/usr/bin/nft", strings.Repeat("5", 64)}, NSenter: DaemonTool{"/usr/bin/nsenter", strings.Repeat("6", 64)},
		RuntimeOrigin: source.Origin, RuntimePublicKey: hex.EncodeToString(source.PublicKey), Resolver: "127.0.0.1:5353",
		Workload: np.MappedIdentity{UID: 40000, GID: 40000, OverflowUID: 40001, OverflowGID: 40001}, Router: np.MappedIdentity{UID: 40002, GID: 40002, OverflowUID: 40003, OverflowGID: 40003},
		SensitiveNetworks: []string{"203.0.113.0/24"}, MaximumTTLSeconds: 20, MaximumInputBytes: 64 << 20, MaximumPolicy: policy}
}

func TestDaemonConfigRequiresClosedBoundedProvisioning(t *testing.T) {
	valid := fixtureDaemonConfig(t)
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeDaemonConfig(raw); err != nil {
		t.Fatal("valid provisioning", err)
	}
	for name, mutate := range map[string]func(*DaemonConfig){
		"version":             func(c *DaemonConfig) { c.Version = 2 },
		"worker-root":         func(c *DaemonConfig) { c.WorkerUID = 0 },
		"worker-map-overlap":  func(c *DaemonConfig) { c.Workload.UID = c.WorkerUID },
		"map-overlap":         func(c *DaemonConfig) { c.Router = c.Workload },
		"relative-path":       func(c *DaemonConfig) { c.BundleRoot = "relative" },
		"root-path":           func(c *DaemonConfig) { c.BundleRoot = "/" },
		"aliased-state":       func(c *DaemonConfig) { c.BundleState = c.CgroupState },
		"untrusted-pin":       func(c *DaemonConfig) { c.RunnerSHA256 = strings.Repeat("0", 64) },
		"missing-sensitive":   func(c *DaemonConfig) { c.SensitiveNetworks = nil },
		"noncanonical-prefix": func(c *DaemonConfig) { c.SensitiveNetworks = []string{"203.0.113.1/24"} },
		"dns-hostname":        func(c *DaemonConfig) { c.Resolver = "resolver.example:53" },
		"dns-unspecified":     func(c *DaemonConfig) { c.Resolver = "0.0.0.0:53" },
		"empty-input-budget":  func(c *DaemonConfig) { c.MaximumInputBytes = 0 },
		"large-input-budget":  func(c *DaemonConfig) { c.MaximumInputBytes = 65 << 30 },
		"policy-unknown":      func(c *DaemonConfig) { c.MaximumPolicy = []byte(`{"unknown":true}`) },
	} {
		t.Run(name, func(t *testing.T) {
			var value DaemonConfig
			if json.Unmarshal(raw, &value) != nil {
				t.Fatal("fixture")
			}
			mutate(&value)
			changed, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := decodeDaemonConfig(changed); err == nil || got != nil {
				t.Fatal("invalid provisioning accepted")
			}
		})
	}
	for _, changed := range [][]byte{
		append(append([]byte(nil), raw...), []byte(` {}`)...),
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"Version":1`), 1),
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"gatewayCredential":"forbidden"`), 1),
		[]byte("null"), bytes.Repeat([]byte(" "), (64<<10)+1), []byte{0xff},
	} {
		if got, err := decodeDaemonConfig(changed); err == nil || got != nil {
			t.Fatal("malformed configuration accepted")
		}
	}
}

func TestDaemonPartialAndZeroOwnersCannotServe(t *testing.T) {
	for _, daemon := range []*Daemon{nil, {}, {ctx: context.Background()}} {
		if daemon.Serve() == nil {
			t.Fatal("unprovisioned daemon served")
		}
		if daemon.Close(context.Background()) != nil {
			t.Fatal("empty owner could not retire")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if owner, err := OpenDaemon(ctx, fixtureDaemonConfig(t)); err == nil || owner != nil {
		t.Fatal("cancelled daemon acquired ownership")
	}
	if value, err := LoadDaemonConfig(ctx, "/not-read"); err == nil || value != nil {
		t.Fatal("cancelled config opened")
	}
}
