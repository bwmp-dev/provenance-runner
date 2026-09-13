package networkpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestReleasedNetworkV2ActualGeneratedWireAndCompleteIdentity(t *testing.T) {
	raw, err := os.ReadFile("testdata/released-v2-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "16118081708038af0b324444a3ecab8cbc6b07e6e681b510fe50a6558293c1ca" {
		t.Fatal("released vector digest mismatch")
	}
	var vector struct {
		Enabled, EffectivePolicy                                                                                         json.RawMessage
		EnabledPolicyHex, EffectivePolicyWireHex, EffectivePolicySha256, LegacyFullPolicyWireHex, LegacyFullPolicySha256 string
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	var policy runnerv1.NetworkPolicyV2
	if err = protojson.Unmarshal(vector.Enabled, &policy); err != nil {
		t.Fatal(err)
	}
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&policy)
	if err != nil || hex.EncodeToString(wire) != vector.EnabledPolicyHex {
		t.Fatal("generated tuple wire mismatch", err)
	}
	var effective runnerv1.EffectivePolicy
	if err = protojson.Unmarshal(vector.EffectivePolicy, &effective); err != nil {
		t.Fatal(err)
	}
	wire, err = (proto.MarshalOptions{Deterministic: true}).Marshal(&effective)
	digest = sha256.Sum256(wire)
	if err != nil || hex.EncodeToString(wire) != vector.EffectivePolicyWireHex || hex.EncodeToString(digest[:]) != vector.EffectivePolicySha256 {
		t.Fatal("complete generated effective policy identity mismatch", err)
	}
	legacy, err := hex.DecodeString(vector.LegacyFullPolicyWireHex)
	if err != nil {
		t.Fatal(err)
	}
	var old runnerv1.EffectivePolicy
	if err = proto.Unmarshal(legacy, &old); err != nil {
		t.Fatal(err)
	}
	wire, err = (proto.MarshalOptions{Deterministic: true}).Marshal(&old)
	digest = sha256.Sum256(wire)
	if err != nil || hex.EncodeToString(wire) != vector.LegacyFullPolicyWireHex || hex.EncodeToString(digest[:]) != vector.LegacyFullPolicySha256 || old.GetNetworkV2() != nil {
		t.Fatal("legacy policy identity changed", err)
	}
	if int32(runnerv1.ProtocolFeature_PROTOCOL_FEATURE_NETWORK_POLICY_V2) != 9 || effective.ProtoReflect().Descriptor().Fields().ByName("network_v2").Number() != 16 {
		t.Fatal("released field identity")
	}
}
