//go:build linux

package networkpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"os"
	"sort"
)

func (h *HostUplink) configure(ctx context.Context) error {
	for _, mac := range []string{h.router.Address, h.host.Address} {
		parsed, err := net.ParseMAC(mac)
		if err != nil || len(parsed) != 6 || parsed[0]&1 != 0 {
			return ErrNamespace
		}
	}
	for _, side := range []struct {
		namespace                       *os.File
		name, v4, v6, peer4, peer6, mac string
	}{
		{h.pair.carrier.network, "wan0", "10.0.2.1", "fd00:2::1", "10.0.2.2", "fd00:2::2", h.host.Address},
		{h.pair.peer, h.record.hostName(), "10.0.2.2", "fd00:2::2", "10.0.2.1", "fd00:2::1", h.router.Address},
	} {
		for _, args := range [][]string{
			{"link", "set", "dev", side.name, "addrgenmode", "none"},
			{"addr", "add", side.v4 + "/24", "dev", side.name},
			{"-6", "addr", "add", side.v6 + "/64", "dev", side.name, "nodad"},
			{"link", "set", "dev", side.name, "up"},
			{"neigh", "replace", side.peer4, "lladdr", side.mac, "nud", "permanent", "dev", side.name},
			{"neigh", "replace", side.peer6, "lladdr", side.mac, "nud", "permanent", "dev", side.name},
		} {
			if _, err := h.pair.execute(ctx, side.namespace, args...); err != nil {
				return err
			}
		}
	}
	for _, route := range []struct {
		namespace *os.File
		args      []string
	}{
		{h.pair.carrier.network, []string{"route", "add", "default", "via", "10.0.2.2", "dev", "wan0"}},
		{h.pair.carrier.network, []string{"-6", "route", "add", "default", "via", "fd00:2::2", "dev", "wan0"}},
		{h.pair.peer, []string{"route", "add", "10.0.1.0/24", "via", "10.0.2.1", "dev", h.record.hostName()}},
		{h.pair.peer, []string{"-6", "route", "add", "fd00:1::/64", "via", "fd00:2::1", "dev", h.record.hostName()}},
	} {
		if _, err := h.pair.execute(ctx, route.namespace, route.args...); err != nil {
			return err
		}
	}
	return nil
}

func uplinkAddresses(rows []map[string]any, name, v4, v6, mac string) bool {
	if len(rows) != 1 || rows[0]["ifname"] != name || rows[0]["address"] != mac {
		return false
	}
	row := rows[0]
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
	return true
}

func uplinkRoutes(rows []map[string]any, name string, host, v6 bool) bool {
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
	if len(rows) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, row := range rows {
		dst, ok := row["dst"].(string)
		if !ok || seen[dst] || (row["dev"] != nil && row["dev"] != name) || row["multipath"] != nil || row["nexthops"] != nil {
			return false
		}
		seen[dst] = true
		if kind, ok := row["type"].(string); ok && kind != "unicast" {
			return false
		}
		if dst == connected {
			if row["gateway"] != nil {
				return false
			}
		} else if dst != destination || row["gateway"] != gateway {
			return false
		}
	}
	return true
}

func uplinkNeighbors(rows []map[string]any, v4, v6, mac string) bool {
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

func (h *HostUplink) observeLayout(ctx context.Context) ([32]byte, error) {
	var observations []any
	for _, host := range []bool{false, true} {
		namespace, name, v4, v6, peer4, peer6, mac, peerMAC := h.pair.carrier.network, "wan0", "10.0.2.1", "fd00:2::1", "10.0.2.2", "fd00:2::2", h.router.Address, h.host.Address
		if host {
			namespace, name, v4, v6, peer4, peer6, mac, peerMAC = h.pair.peer, h.record.hostName(), "10.0.2.2", "fd00:2::2", "10.0.2.1", "fd00:2::1", h.host.Address, h.router.Address
		}
		for i, args := range [][]string{{"-j", "addr", "show", "dev", name}, {"-j", "-4", "route", "show", "table", "main", "dev", name}, {"-j", "-6", "route", "show", "table", "main", "dev", name}, {"-j", "neigh", "show", "dev", name}} {
			raw, err := h.pair.execute(ctx, namespace, args...)
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
				valid = uplinkAddresses(rows, name, v4, v6, mac)
			case 1, 2:
				valid = uplinkRoutes(rows, name, host, i == 2)
			case 3:
				valid = uplinkNeighbors(rows, peer4, peer6, peerMAC)
			}
			if !valid {
				return [32]byte{}, ErrNamespace
			}
			sort.Slice(rows, func(a, b int) bool {
				x, _ := json.Marshal(rows[a])
				y, _ := json.Marshal(rows[b])
				return string(x) < string(y)
			})
			observations = append(observations, rows)
		}
	}
	raw, err := json.Marshal(observations)
	if err != nil {
		return [32]byte{}, ErrNamespace
	}
	return sha256.Sum256(raw), nil
}
