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
type strictProtocolCodec struct{}

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

func (strictProtocolCodec) Unmarshal(data []byte, value any) error {
	message, ok := value.(proto.Message)
	if !ok {
		return fmt.Errorf("protobuf codec cannot unmarshal %T", value)
	}
	if _, gatewayMessage := value.(*runnerv1.GatewayMessage); gatewayMessage {
		// Inspect the wire before decoding: protobuf oneof replacement could
		// otherwise allocate then discard a secret delivery hidden by a later
		// payload. This runner does not yet negotiate secret delivery.
		deliveries, err := messageFieldPayloads(data, 32)
		if err != nil {
			return errors.New("gateway message has malformed protobuf framing")
		}
		if len(deliveries) != 0 {
			return errors.New("unsolicited test-secret delivery")
		}
		occurrences, err := countJobCorrelationWireOccurrences(data)
		if err != nil {
			return errors.New("gateway message has malformed protobuf framing")
		}
		if occurrences > 1 {
			return errors.New("gateway lease offer contains duplicate job correlation carriers")
		}
	}
	return proto.Unmarshal(data, message)
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
