//go:build linux

package networkpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
)

func (l *PrivateJobLink) configureLayout(ctx context.Context) error {
	for _, mac := range []string{l.routerIdentity.Address, l.peerIdentity.Address} {
		parsed, err := net.ParseMAC(mac)
		if err != nil || len(parsed) != 6 || parsed[0]&1 != 0 {
			return ErrNamespace
		}
	}
	for _, item := range []struct {
		namespace    *os.File
		name, v4, v6 string
	}{
		{l.carrier.network, "job0", "10.0.1.1", "fd00:1::1"}, {l.peer, "eth0", "10.0.1.2", "fd00:1::2"},
	} {
		for _, args := range [][]string{
			{"link", "set", "dev", item.name, "addrgenmode", "none"},
			{"addr", "add", item.v4 + "/24", "dev", item.name},
			{"-6", "addr", "add", item.v6 + "/64", "dev", item.name, "nodad"},
			{"link", "set", "dev", "lo", "up"},
			{"link", "set", "dev", item.name, "up"},
		} {
			if _, err := l.execute(ctx, item.namespace, args...); err != nil {
				return err
			}
		}
	}
	for _, item := range []struct {
		namespace         *os.File
		name, v4, v6, mac string
	}{
		{l.carrier.network, "job0", "10.0.1.2", "fd00:1::2", l.peerIdentity.Address},
		{l.peer, "eth0", "10.0.1.1", "fd00:1::1", l.routerIdentity.Address},
	} {
		for _, address := range []string{item.v4, item.v6} {
			if _, err := l.execute(ctx, item.namespace, "neigh", "replace", address, "lladdr", item.mac, "nud", "permanent", "dev", item.name); err != nil {
				return err
			}
		}
	}
	for _, args := range [][]string{{"route", "add", "default", "via", "10.0.1.1", "dev", "eth0"}, {"-6", "route", "add", "default", "via", "fd00:1::1", "dev", "eth0"}} {
		if _, err := l.execute(ctx, l.peer, args...); err != nil {
			return err
		}
	}
	return nil
}

func layoutRows(raw []byte) ([]map[string]any, error) {
	var rows []map[string]any
	if len(raw) > 65536 || json.Unmarshal(raw, &rows) != nil || len(rows) > 16 {
		return nil, ErrNamespace
	}
	return rows, nil
}

func addressLayout(rows []map[string]any, peer bool) bool {
	name, v4, v6 := "job0", "10.0.1.1", "fd00:1::1"
	want := 1
	if peer {
		name, v4, v6, want = "eth0", "10.0.1.2", "fd00:1::2", 2
	}
	if len(rows) != want {
		return false
	}
	found := false
	for _, row := range rows {
		if peer && row["ifname"] == "lo" {
			continue
		}
		if found || row["ifname"] != name {
			return false
		}
		found = true
		flags, ok := row["flags"].([]any)
		if !ok {
			return false
		}
		up := false
		for _, flag := range flags {
			if flag == "UP" {
				up = true
			}
		}
		addresses, ok := row["addr_info"].([]any)
		if !ok || !up || len(addresses) != 2 {
			return false
		}
		seen := map[string]bool{}
		for _, value := range addresses {
			address, ok := value.(map[string]any)
			if !ok {
				return false
			}
			local, ok := address["local"].(string)
			if !ok || seen[local] || address["scope"] != "global" {
				return false
			}
			seen[local] = true
			if !((local == v4 && address["family"] == "inet" && address["prefixlen"] == float64(24)) || (local == v6 && address["family"] == "inet6" && address["prefixlen"] == float64(64))) {
				return false
			}
		}
	}
	return found
}

func routeLayout(rows []map[string]any, peer, v6 bool) bool {
	name, prefix, gateway := "job0", "10.0.1.0/24", "10.0.1.1"
	want := 1
	if peer {
		name, want = "eth0", 2
	}
	if v6 {
		prefix, gateway = "fd00:1::/64", "fd00:1::1"
	}
	if len(rows) != want {
		return false
	}
	seen := map[string]bool{}
	for _, row := range rows {
		dst, ok := row["dst"].(string)
		// ip omits dev when the query itself is scoped to that interface.
		deviceValid := row["dev"] == name || (!peer && row["dev"] == nil)
		if !ok || seen[dst] || !deviceValid || row["multipath"] != nil || row["nexthops"] != nil {
			return false
		}
		seen[dst] = true
		if dst == prefix {
			if row["gateway"] != nil {
				return false
			}
		} else if !peer || dst != "default" || row["gateway"] != gateway {
			return false
		}
		if kind, ok := row["type"].(string); ok && kind != "unicast" {
			return false
		}
	}
	return true
}

func neighborLayout(rows []map[string]any, peer bool, routerMAC, peerMAC string) bool {
	v4, v6, mac := "10.0.1.2", "fd00:1::2", peerMAC
	if peer {
		v4, v6, mac = "10.0.1.1", "fd00:1::1", routerMAC
	}
	if len(rows) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, row := range rows {
		dst, ok := row["dst"].(string)
		state, valid := row["state"].([]any)
		if !ok || seen[dst] || (dst != v4 && dst != v6) || row["lladdr"] != mac || !valid || len(state) != 1 || state[0] != "PERMANENT" {
			return false
		}
		seen[dst] = true
	}
	return true
}

// Observe both address sets, main-table routes and permanent neighbors. No
// traffic counters are requested; set-like row ordering is canonicalized.
func (l *PrivateJobLink) observeLayout(ctx context.Context) ([32]byte, error) {
	var observations []any
	for _, peer := range []bool{false, true} {
		namespace, name := l.carrier.network, "job0"
		if peer {
			namespace, name = l.peer, "eth0"
		}
		queries := [][]string{{"-j", "addr", "show"}, {"-j", "-4", "route", "show", "table", "main"}, {"-j", "-6", "route", "show", "table", "main"}, {"-j", "neigh", "show", "dev", name}}
		if !peer {
			for i := 0; i < 3; i++ {
				queries[i] = append(queries[i], "dev", name)
			}
		}
		for i, args := range queries {
			raw, err := l.execute(ctx, namespace, args...)
			if err != nil {
				return [32]byte{}, err
			}
			rows, err := layoutRows(raw)
			if err != nil {
				return [32]byte{}, err
			}
			valid := false
			switch i {
			case 0:
				valid = addressLayout(rows, peer)
			case 1, 2:
				valid = routeLayout(rows, peer, i == 2)
			case 3:
				valid = neighborLayout(rows, peer, l.routerIdentity.Address, l.peerIdentity.Address)
			}
			if !valid {
				return [32]byte{}, fmt.Errorf("private layout peer=%t observation=%d: %w", peer, i, ErrNamespace)
			}
			sort.Slice(rows, func(a, b int) bool {
				x, _ := json.Marshal(rows[a])
				y, _ := json.Marshal(rows[b])
				return string(x) < string(y)
			})
			observations = append(observations, rows)
			encoded, _ := json.Marshal(rows)
			part := sha256.Sum256(encoded)
			index := len(observations) - 1
			if l.layout != ([32]byte{}) && l.layoutParts[index] != part {
				return [32]byte{}, fmt.Errorf("private layout drift peer=%t observation=%d: %w", peer, i, ErrNamespace)
			}
			if l.layout == ([32]byte{}) {
				l.layoutParts[index] = part
			}
		}
	}
	raw, err := json.Marshal(observations)
	if err != nil {
		return [32]byte{}, ErrNamespace
	}
	return sha256.Sum256(raw), nil
}
