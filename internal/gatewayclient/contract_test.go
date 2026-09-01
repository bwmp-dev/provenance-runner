package gatewayclient

import (
	"testing"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestAlpha3ContractFieldNumbersAndFeature(t *testing.T) {
	fields := []struct {
		message protoreflect.MessageDescriptor
		name    protoreflect.Name
		number  protoreflect.FieldNumber
	}{
		{(&runnerv1.Capabilities{}).ProtoReflect().Descriptor(), "features", 16},
		{(&runnerv1.DependencyInput{}).ProtoReflect().Descriptor(), "plugin_name", 10},
		{(&runnerv1.JobSpecification{}).ProtoReflect().Descriptor(), "target_plugin_name", 20},
		{(&runnerv1.GatewayMessage{}).ProtoReflect().Descriptor(), "event_acknowledgement", 30},
		{(&runnerv1.GatewayMessage{}).ProtoReflect().Descriptor(), "heartbeat_acknowledgement", 31},
	}
	for _, field := range fields {
		descriptor := field.message.Fields().ByName(field.name)
		if descriptor == nil || descriptor.Number() != field.number {
			t.Fatalf("%s.%s field = %#v, want number %d", field.message.FullName(), field.name, descriptor, field.number)
		}
	}
	if runnerv1.ProtocolFeature_PROTOCOL_FEATURE_DURABLE_LEASE_ACKNOWLEDGEMENTS.Number() != 1 {
		t.Fatalf("durable acknowledgement feature = %d, want 1", runnerv1.ProtocolFeature_PROTOCOL_FEATURE_DURABLE_LEASE_ACKNOWLEDGEMENTS.Number())
	}
}
