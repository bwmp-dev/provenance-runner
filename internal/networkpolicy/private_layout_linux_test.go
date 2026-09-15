//go:build linux

package networkpolicy

import (
	"encoding/json"
	"testing"
)

func TestPrivateLayoutRejectsAlternateRoutesAndNeighbors(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		prefix, gateway := "10.0.1.0/24", "10.0.1.1"
		if v6 {
			prefix, gateway = "fd00:1::/64", "fd00:1::1"
		}
		valid := []map[string]any{{"dst": prefix, "dev": "eth0"}, {"dst": "default", "dev": "eth0", "gateway": gateway}}
		if !routeLayout([]map[string]any{{"dst": prefix}}, false, v6) {
			t.Fatal("interface-scoped router output refused")
		}
		if !routeLayout(valid, true, v6) {
			t.Fatal("closed layout refused")
		}
		for _, mutate := range []func([]map[string]any){
			func(rows []map[string]any) { rows[1]["gateway"] = "foreign" },
			func(rows []map[string]any) { rows[1]["dev"] = "bypass" },
			func(rows []map[string]any) { rows[1]["type"] = "blackhole" },
			func(rows []map[string]any) { rows[1]["nexthops"] = []any{} },
			func(rows []map[string]any) { rows[0]["gateway"] = gateway },
			func(rows []map[string]any) { rows[0]["dst"] = "default" },
		} {
			raw, _ := json.Marshal(valid)
			rows, err := layoutRows(raw)
			if err != nil {
				t.Fatal(err)
			}
			mutate(rows)
			if routeLayout(rows, true, v6) {
				t.Fatal("alternate routing admitted")
			}
		}
	}
	mac := "02:00:00:00:00:01"
	neighbors := []map[string]any{{"dst": "10.0.1.1", "lladdr": mac, "state": []any{"PERMANENT"}}, {"dst": "fd00:1::1", "lladdr": mac, "state": []any{"PERMANENT"}}}
	if !neighborLayout(neighbors, true, mac, "unused") {
		t.Fatal("permanent peers refused")
	}
	neighbors[0]["state"] = []any{"REACHABLE"}
	if neighborLayout(neighbors, true, mac, "unused") {
		t.Fatal("mutable neighbor admitted")
	}
	if _, err := layoutRows([]byte(`{} {}`)); err == nil {
		t.Fatal("ambiguous layout JSON")
	}
}

func TestPrivateAddressLayoutRequiresExactWorkloadInterfaces(t *testing.T) {
	rows := []map[string]any{{"ifname": "lo"}, {"ifname": "eth0", "flags": []any{"UP"}, "addr_info": []any{
		map[string]any{"local": "10.0.1.2", "family": "inet", "prefixlen": float64(24), "scope": "global"},
		map[string]any{"local": "fd00:1::2", "family": "inet6", "prefixlen": float64(64), "scope": "global"},
	}}}
	if !addressLayout(rows, true) {
		t.Fatal("closed addresses refused")
	}
	if addressLayout(append(rows, map[string]any{"ifname": "bypass"}), true) {
		t.Fatal("extra workload interface admitted")
	}
	rows[1]["flags"] = []any{"DOWN"}
	if addressLayout(rows, true) {
		t.Fatal("inactive workload interface admitted")
	}
}
