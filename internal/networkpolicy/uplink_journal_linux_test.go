//go:build linux

package networkpolicy

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestUplinkRecordRejectsAmbiguousOwnership(t *testing.T) {
	id := "10000000-0000-4000-8000-000000000001"
	r := uplinkRecord{Version: 1, Token: strings.Repeat("a", 64), Boot: id, NetworkDev: 4, NetworkIno: 123, Job: id, Lease: id, Execution: id, Attempt: id, Candidate: id, Matrix: id, AttemptNumber: 1, Policy: strings.Repeat("b", 64)}
	raw, _ := json.Marshal(r)
	raw = append(raw, '\n')
	if got, err := decodeUplinkRecord(raw, r.Token+".json"); err != nil || got != r {
		t.Fatal("canonical intent refused")
	}
	if len(r.hostName()) != 15 || len(r.routerStage()) != 15 || r.hostName() == r.routerStage() {
		t.Fatal("bounded generated names")
	}
	for _, invalid := range [][]byte{nil, []byte("{}"), append(append([]byte{}, raw...), raw...), []byte(strings.Repeat("x", 4097)), append([]byte(" "), raw...)} {
		if _, err := decodeUplinkRecord(invalid, r.Token+".json"); err == nil {
			t.Fatal("ambiguous intent accepted")
		}
	}
	for _, name := range []string{"../" + r.Token + ".json", r.Token + ".owned.json", strings.Repeat("c", 64) + ".json"} {
		if _, err := decodeUplinkRecord(raw, name); err == nil {
			t.Fatal("foreign intent filename accepted")
		}
	}
	for _, mutate := range []func(*uplinkRecord){func(r *uplinkRecord) { r.Token = "short" }, func(r *uplinkRecord) { r.NetworkIno = 0 }, func(r *uplinkRecord) { r.NetworkDev = 0 }, func(r *uplinkRecord) { r.AttemptNumber = 0 }, func(r *uplinkRecord) { r.AttemptNumber = 4 }, func(r *uplinkRecord) { r.Policy = "requested" }, func(r *uplinkRecord) { r.Job = "foreign" }, func(r *uplinkRecord) { r.Boot = "" }} {
		copy := r
		mutate(&copy)
		if validUplinkRecord(copy) {
			t.Fatal("invalid ownership accepted")
		}
	}
}

func TestHostUplinkRequiresActualOwners(t *testing.T) {
	if journal, err := OpenHostUplinkJournal(nil, RouteTools{}); journal != nil || err == nil {
		t.Fatal("missing host authority accepted")
	}
	for _, journal := range []*HostUplinkJournal{nil, {}} {
		if journal.Recover(context.Background()) == nil {
			t.Fatal("missing journal recovery accepted")
		}
		if uplink, err := journal.Create(context.Background(), nil, nil); uplink != nil || err == nil {
			t.Fatal("missing job accepted")
		}
		if journal.Close() != nil || journal.Close() != nil {
			t.Fatal("empty journal cleanup")
		}
	}
	var uplink *HostUplink
	if uplink.Validate(context.Background()) == nil || uplink.Close(context.Background()) != nil {
		t.Fatal("nil uplink handling")
	}
}

func TestHostUplinkRefusesOverlappingPrefixes(t *testing.T) {
	for _, prefix := range []string{"10.0.1.2/32", "10.0.2.0/24", "10.0.0.0/8", "fd00:1::/64", "fd00:2::1/128", "fd00::/8"} {
		if !overlapsUplink(netip.MustParsePrefix(prefix)) {
			t.Fatal("conflicting prefix admitted", prefix)
		}
	}
	for _, prefix := range []string{"127.0.0.0/8", "1.1.1.1/32", "172.17.0.0/16", "fd00:3::/64", "::1/128"} {
		if overlapsUplink(netip.MustParsePrefix(prefix)) {
			t.Fatal("unrelated prefix refused", prefix)
		}
	}
}

func TestHostUplinkRouteAndNeighborShape(t *testing.T) {
	for _, host := range []bool{false, true} {
		for _, v6 := range []bool{false, true} {
			connected, destination, gateway := "10.0.2.0/24", "default", "10.0.2.2"
			if host {
				destination, gateway = "10.0.1.0/24", "10.0.2.1"
			}
			if v6 {
				connected, gateway = "fd00:2::/64", "fd00:2::2"
				if host {
					destination, gateway = "fd00:1::/64", "fd00:2::1"
				}
			}
			rows := []map[string]any{{"dst": connected}, {"dst": destination, "gateway": gateway}}
			if !uplinkRoutes(rows, "owned", host, v6) {
				t.Fatal("fixed route shape refused")
			}
			rows[1]["gateway"] = "foreign"
			if uplinkRoutes(rows, "owned", host, v6) {
				t.Fatal("foreign gateway accepted")
			}
		}
	}
	mac := "02:00:00:00:00:01"
	rows := []map[string]any{{"dst": "10.0.2.1", "lladdr": mac, "state": []any{"PERMANENT"}}, {"dst": "fd00:2::1", "lladdr": mac, "state": []any{"PERMANENT"}}}
	if !uplinkNeighbors(rows, "10.0.2.1", "fd00:2::1", mac) {
		t.Fatal("permanent neighbor shape refused")
	}
	rows[0]["lladdr"] = "02:00:00:00:00:02"
	if uplinkNeighbors(rows, "10.0.2.1", "fd00:2::1", mac) {
		t.Fatal("foreign MAC accepted")
	}
}
