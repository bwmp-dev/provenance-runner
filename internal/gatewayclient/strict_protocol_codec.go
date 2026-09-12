package gatewayclient

import (
	"errors"
	"fmt"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// strictProtocolCodec preserves the standard protobuf content subtype while
// enforcing IFC-012 invariants that generated object unmarshalling cannot
// observe. In particular, protobuf merges duplicate singular message fields;
// the raw Connect response must therefore be checked before proto.Unmarshal.
type strictProtocolCodec struct{ allowTestSecrets bool }

func (strictProtocolCodec) Name() string { return "proto" }

func (strictProtocolCodec) Marshal(value any) ([]byte, error) {
	message, ok := value.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("protobuf codec cannot marshal %T", value)
	}
	if runner, ok := value.(*runnerv1.RunnerMessage); ok {
		if err := terminalMessageBound(runner); err != nil {
			return nil, err
		}
	}
	return proto.Marshal(message)
}

func (c strictProtocolCodec) Unmarshal(data []byte, value any) error {
	message, ok := value.(proto.Message)
	if !ok {
		return fmt.Errorf("protobuf codec cannot unmarshal %T", value)
	}
	if _, gatewayMessage := value.(*runnerv1.GatewayMessage); gatewayMessage {
		// Inspect the wire before decoding: protobuf oneof replacement could
		// otherwise allocate then discard a secret delivery hidden by a later
		// payload. The enlarged variant is available only to enabled consumers.
		deliveries, err := messageFieldPayloads(data, 32)
		if err != nil {
			return errors.New("gateway message has malformed protobuf framing")
		}
		if len(deliveries) != 0 {
			if !c.allowTestSecrets {
				return errors.New("unsolicited test-secret delivery")
			}
			if len(deliveries) != 1 || len(data) > maximumSecretDeliveryBytes || !validSecretDeliveryWire(data, deliveries[0]) {
				return errors.New("test-secret delivery framing refused")
			}
		} else if len(data) > MaximumMessageBytes {
			return errors.New("gateway message exceeds size limit")
		}
		occurrences, err := countJobCorrelationWireOccurrences(data)
		if err != nil {
			return errors.New("gateway message has malformed protobuf framing")
		}
		if occurrences > 1 {
			return errors.New("gateway lease offer contains duplicate job correlation carriers")
		}
	}
	err := proto.Unmarshal(data, message)
	if err != nil {
		if gateway, ok := value.(*runnerv1.GatewayMessage); ok {
			clearTestSecretDelivery(gateway)
		}
	}
	return err
}

func validSecretDeliveryWire(envelope, delivery []byte) bool {
	for _, field := range []protowire.Number{10, 11, 12, 13, 14, 15, 16, 30, 31} {
		values, err := messageFieldPayloads(envelope, field)
		if err != nil || len(values) != 0 {
			return false
		}
	}
	values, err := messageFieldPayloads(delivery, 4)
	if err != nil || len(values) == 0 || len(values) > 64 {
		return false
	}
	total := 0
	for _, value := range values {
		buffers, err := messageFieldPayloads(value, 2)
		if err != nil || len(buffers) != 1 || len(buffers[0]) == 0 {
			return false
		}
		total += len(buffers[0])
		if total > 65536 {
			return false
		}
	}
	return true
}

func countJobCorrelationWireOccurrences(gateway []byte) (int, error) {
	offers, err := messageFieldPayloads(gateway, 11)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, offer := range offers {
		jobs, err := messageFieldPayloads(offer, 1)
		if err != nil {
			return 0, err
		}
		for _, job := range jobs {
			correlations, err := messageFieldPayloads(job, 21)
			if err != nil {
				return 0, err
			}
			count += len(correlations)
			if count > 1 {
				return count, nil
			}
		}
	}
	return count, nil
}

func messageFieldPayloads(message []byte, wanted protowire.Number) ([][]byte, error) {
	var payloads [][]byte
	for len(message) != 0 {
		number, wireType, tagBytes := protowire.ConsumeTag(message)
		if tagBytes < 0 {
			return nil, protowire.ParseError(tagBytes)
		}
		fieldBytes := message[tagBytes:]
		if number == wanted {
			if wireType != protowire.BytesType {
				return nil, errors.New("nested protobuf message has the wrong wire type")
			}
			payload, valueBytes := protowire.ConsumeBytes(fieldBytes)
			if valueBytes < 0 {
				return nil, protowire.ParseError(valueBytes)
			}
			payloads = append(payloads, payload)
		}
		fieldLength := protowire.ConsumeFieldValue(number, wireType, fieldBytes)
		if fieldLength < 0 {
			return nil, protowire.ParseError(fieldLength)
		}
		message = fieldBytes[fieldLength:]
	}
	return payloads, nil
}
