package gatewayclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestReleasedAlpha7ContractFieldNumbersAndFeatures(t *testing.T) {
	fields := []struct {
		message protoreflect.MessageDescriptor
		name    protoreflect.Name
		number  protoreflect.FieldNumber
	}{
		{(&runnerv1.Capabilities{}).ProtoReflect().Descriptor(), "features", 16},
		{(&runnerv1.DependencyInput{}).ProtoReflect().Descriptor(), "plugin_name", 10},
		{(&runnerv1.JobSpecification{}).ProtoReflect().Descriptor(), "target_plugin_name", 20},
		{(&runnerv1.JobSpecification{}).ProtoReflect().Descriptor(), "job_correlation", 21},
		{(&runnerv1.GatewayMessage{}).ProtoReflect().Descriptor(), "event_acknowledgement", 30},
		{(&runnerv1.GatewayMessage{}).ProtoReflect().Descriptor(), "heartbeat_acknowledgement", 31},
		{(&runnerv1.GatewayMessage{}).ProtoReflect().Descriptor(), "credential_rotation", 15},
		{(&runnerv1.RunnerMessage{}).ProtoReflect().Descriptor(), "credential_rotation_acknowledgement", 30},
		{(&runnerv1.RotateCredential{}).ProtoReflect().Descriptor(), "issued_at", 10},
		{(&runnerv1.RotateCredential{}).ProtoReflect().Descriptor(), "credential_fingerprint", 11},
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
	if runnerv1.ProtocolFeature_PROTOCOL_FEATURE_CREDENTIAL_ROTATION.Number() != 2 {
		t.Fatalf("credential rotation feature = %d, want 2", runnerv1.ProtocolFeature_PROTOCOL_FEATURE_CREDENTIAL_ROTATION.Number())
	}
	if runnerv1.ProtocolFeature_PROTOCOL_FEATURE_JOB_CORRELATION_V1.Number() != 3 {
		t.Fatalf("job correlation feature = %d, want 3", runnerv1.ProtocolFeature_PROTOCOL_FEATURE_JOB_CORRELATION_V1.Number())
	}
}

func TestExpectedProtocolModuleAuthority(t *testing.T) {
	const authority = "v0.0.0-20260904081456-85db7a428d42"
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	contents, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	fields := strings.Fields(string(contents))
	for index, field := range fields {
		if field == "github.com/bwmp-dev/provenance/gen/proto" && index+1 < len(fields) {
			if fields[index+1] != authority {
				t.Fatalf("protocol module = %s, want %s", fields[index+1], authority)
			}
			return
		}
	}
	t.Fatal("released protocol module is absent from go.mod")
}
