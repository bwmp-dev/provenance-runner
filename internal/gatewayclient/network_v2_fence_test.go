package gatewayclient

import (
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func TestReleasedNetworkV2CannotActivateOfferOrCapability(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	for _, mixed := range []bool{false, true} {
		for _, mode := range []runnerv1.NetworkMode{runnerv1.NetworkMode_NETWORK_MODE_NONE, runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST} {
			offer := validLeaseOffer(now)
			offer.Job.EffectivePolicy.NetworkV2 = &runnerv1.NetworkPolicyV2{Mode: mode}
			if !mixed {
				offer.Job.EffectivePolicy.Network = nil
			}
			before := proto.Clone(offer)
			rejection := validateOffer(offer, validOfferConfig(), now, 10*time.Minute, false, false)
			if rejection == nil || rejection.Code != "unsupported_network" || !proto.Equal(before, offer) {
				t.Fatal("unnegotiated v2 policy accepted, downgraded or mutated", rejection)
			}
		}
	}
	features := []runnerv1.ProtocolFeature{
		runnerv1.ProtocolFeature_PROTOCOL_FEATURE_DURABLE_LEASE_ACKNOWLEDGEMENTS,
		runnerv1.ProtocolFeature_PROTOCOL_FEATURE_JOB_CORRELATION_V1,
		runnerv1.ProtocolFeature_PROTOCOL_FEATURE_NETWORK_POLICY_V2,
	}
	if validateAdvertisedFeatures(features) == nil {
		t.Fatal("unimplemented network feature accepted")
	}
}
