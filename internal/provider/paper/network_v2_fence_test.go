package paper

import (
	"testing"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func TestAdaptJobRefusesExclusiveAndMixedNetworkV2(t *testing.T) {
	provider, server, payloads := validationTestProvider(t)
	for _, mixed := range []bool{false, true} {
		specification := validRemoteSpecification(t, server.URL, payloads)
		specification.EffectivePolicy.NetworkV2 = &runnerv1.NetworkPolicyV2{Mode: runnerv1.NetworkMode_NETWORK_MODE_NONE}
		if !mixed {
			specification.EffectivePolicy.Network = nil
		}
		before := proto.Clone(specification)
		if _, err := provider.AdaptJob(specification); err == nil || !proto.Equal(before, specification) {
			t.Fatal("adapter accepted, downgraded or mutated network v2")
		}
	}
}
