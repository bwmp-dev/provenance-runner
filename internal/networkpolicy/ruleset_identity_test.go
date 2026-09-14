package networkpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

func rulesetFixture(t *testing.T) map[string]any {
	t.Helper()
	const table = "pv_10000000000040008000000000000001"
	items := []any{map[string]any{"metainfo": map[string]any{"version": "synthetic"}}, map[string]any{"table": map[string]any{"family": "inet", "name": table, "handle": 1}}}
	for index, name := range []string{"input", "output", "forward"} {
		items = append(items, map[string]any{"chain": map[string]any{"family": "inet", "table": table, "name": name, "type": "filter", "hook": name, "prio": 0, "policy": "drop", "handle": index + 2}})
	}
	items = append(items,
		map[string]any{"counter": map[string]any{"family": "inet", "table": table, "name": "forwarded", "packets": 0, "bytes": 0, "handle": 5}},
		map[string]any{"limit": map[string]any{"family": "inet", "table": table, "name": "bandwidth", "rate": 64, "rate_unit": "kbytes", "per": "second", "inv": true, "handle": 6}},
		map[string]any{"set": map[string]any{"family": "inet", "table": table, "name": "allowed4", "type": []any{"ipv4_addr", "inet_proto", "inet_service"}, "flags": []any{"timeout"}, "timeout": 30, "size": 4096, "handle": 7, "elem": []any{map[string]any{"elem": map[string]any{"val": map[string]any{"concat": []any{"1.1.1.1", "tcp", 8080}}, "expires": 29}}, map[string]any{"elem": map[string]any{"val": map[string]any{"concat": []any{"1.1.1.1", "udp", 8081}}, "expires": 29}}}}},
		map[string]any{"set": map[string]any{"family": "inet", "table": table, "name": "connections", "type": "mark", "size": 1, "flags": []any{"dynamic"}, "handle": 8}},
		map[string]any{"rule": map[string]any{"family": "inet", "table": table, "chain": "forward", "handle": 9, "expr": []any{map[string]any{"match": map[string]any{"op": ">=", "left": map[string]any{"meta": map[string]any{"key": "time"}}, "right": "2026-09-14 02:00:00"}}, map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}, map[string]any{"drop": nil}}}},
		map[string]any{"rule": map[string]any{"family": "inet", "table": table, "chain": "forward", "handle": 10, "expr": []any{map[string]any{"ct count": map[string]any{"val": 16, "inv": true}}, map[string]any{"drop": nil}}}},
	)
	return map[string]any{"nftables": items}
}

func rulesetBody(root map[string]any, index int, kind string) map[string]any {
	return root["nftables"].([]any)[index].(map[string]any)[kind].(map[string]any)
}
func rulesetHash(t *testing.T, root map[string]any) ([32]byte, error) {
	t.Helper()
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return kernelRulesetIdentity(raw, "10000000-0000-4000-8000-000000000001")
}

func TestKernelRulesetIdentityKeepsBudgetsAndGrantSemantics(t *testing.T) {
	baseline, err := rulesetHash(t, rulesetFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(map[string]any){
		"budget recreated":   func(r map[string]any) { rulesetBody(r, 6, "limit")["handle"] = 66 },
		"budget expanded":    func(r map[string]any) { rulesetBody(r, 6, "limit")["rate"] = 128 },
		"conn set expanded":  func(r map[string]any) { rulesetBody(r, 8, "set")["size"] = 2 },
		"conn set recreated": func(r map[string]any) { rulesetBody(r, 8, "set")["handle"] = 88 },
		"dynamic cap changed": func(r map[string]any) {
			rulesetBody(r, 8, "set")["elem"] = []any{map[string]any{"elem": map[string]any{"val": 1, "ct count": map[string]any{"val": 17, "inv": true}}}}
		},
		"port changed": func(r map[string]any) {
			rulesetBody(r, 7, "set")["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)["val"].(map[string]any)["concat"].([]any)[2] = 22
		},
		"absolute deadline": func(r map[string]any) {
			rulesetBody(r, 9, "rule")["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = "2026-09-14 03:00:00"
		},
		"connection ceiling": func(r map[string]any) {
			rulesetBody(r, 10, "rule")["expr"].([]any)[0].(map[string]any)["ct count"].(map[string]any)["val"] = 17
		},
		"rule order":          func(r map[string]any) { items := r["nftables"].([]any); items[9], items[10] = items[10], items[9] },
		"default accept":      func(r map[string]any) { rulesetBody(r, 2, "chain")["policy"] = "accept" },
		"foreign table":       func(r map[string]any) { rulesetBody(r, 7, "set")["table"] = "foreign" },
		"unknown enforcement": func(r map[string]any) { rulesetBody(r, 10, "rule")["unexpected"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			r := rulesetFixture(t)
			change(r)
			got, err := rulesetHash(t, r)
			if err == nil && got == baseline {
				t.Fatal("enforcement drift normalized away")
			}
		})
	}
}

func TestKernelRulesetIdentityIgnoresOnlyVolatileAccounting(t *testing.T) {
	r := rulesetFixture(t)
	baseline, err := rulesetHash(t, r)
	if err != nil {
		t.Fatal(err)
	}
	rulesetBody(r, 5, "counter")["packets"] = 999
	rulesetBody(r, 5, "counter")["bytes"] = 100000
	rulesetBody(r, 9, "rule")["expr"].([]any)[1].(map[string]any)["counter"].(map[string]any)["packets"] = 100
	rulesetBody(r, 8, "set")["elem"] = []any{map[string]any{"elem": map[string]any{"val": 1, "ct count": map[string]any{"val": 16, "inv": true}}}}
	elements := rulesetBody(r, 7, "set")["elem"].([]any)
	for _, element := range elements {
		element.(map[string]any)["elem"].(map[string]any)["expires"] = 12
	}
	elements[0], elements[1] = elements[1], elements[0]
	got, err := rulesetHash(t, r)
	if err != nil || got != baseline {
		t.Fatal("normal packet state changed enforcement identity", err)
	}
}

func TestKernelRulesetIdentityRefusesAmbiguousAndOversizedJSON(t *testing.T) {
	for _, raw := range []string{`{"nftables":[],"nftables":[]}`, `{"nftables":[{"table":{"family":"inet","family":"ip"}}]}`, `{"nftables":[]} true`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), strings.Repeat(" ", 65537)} {
		if _, err := kernelRulesetIdentity([]byte(raw), "10000000-0000-4000-8000-000000000001"); err == nil {
			t.Fatal("ambiguous ruleset accepted")
		}
	}
}
