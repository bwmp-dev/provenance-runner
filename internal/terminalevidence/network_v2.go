package terminalevidence

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

// The caller has validated the complete canonical released configuration. Its
// array order remains part of the configuration hash; sort only this independent
// wire maximum when comparing whole tuples. This is a request, not authority.
func configurationNetworkMaximumV2(raw []byte) (*runnerv1.NetworkPolicyV2, error) {
	var configuration struct {
		Network struct {
			Mode                  string `json:"mode"`
			MaximumConnections    uint32 `json:"maximumConnections"`
			MaximumBytesPerSecond uint32 `json:"maximumBytesPerSecond"`
			Permissions           []struct {
				Hostname  string `json:"hostname"`
				Port      uint32 `json:"port"`
				Transport string `json:"transport"`
			} `json:"permissions"`
		} `json:"network"`
	}
	if json.Unmarshal(raw, &configuration) != nil {
		return nil, ErrInvalid
	}
	network := configuration.Network
	mode, ok := map[string]runnerv1.NetworkMode{"none": runnerv1.NetworkMode_NETWORK_MODE_NONE, "restricted": runnerv1.NetworkMode_NETWORK_MODE_RESTRICTED, "allowlist": runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST}[network.Mode]
	if !ok {
		return nil, ErrInvalid
	}
	maximum := &runnerv1.NetworkPolicyV2{Mode: mode, MaximumConnections: network.MaximumConnections, MaximumBytesPerSecond: network.MaximumBytesPerSecond}
	for _, permission := range network.Permissions {
		transport, ok := map[string]runnerv1.NetworkTransportV2{"tcp": runnerv1.NetworkTransportV2_NETWORK_TRANSPORT_V2_TCP, "udp": runnerv1.NetworkTransportV2_NETWORK_TRANSPORT_V2_UDP}[permission.Transport]
		if !ok {
			return nil, ErrInvalid
		}
		maximum.Permissions = append(maximum.Permissions, &runnerv1.NetworkPermissionV2{Hostname: permission.Hostname, Port: permission.Port, Transport: transport})
	}
	slices.SortFunc(maximum.Permissions, func(a, b *runnerv1.NetworkPermissionV2) int {
		if value := strings.Compare(a.Hostname, b.Hostname); value != 0 {
			return value
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
	})
	if networkpolicy.ValidateWireV2(maximum) != nil {
		return nil, ErrInvalid
	}
	return maximum, nil
}
