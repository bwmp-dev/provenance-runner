//go:build linux

package testsecrets

import (
	"regexp"
	"time"
	"unicode/utf8"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const MaximumDeliveryBytes = 98304
const MaximumVersion = uint64(9007199254740991)

var secretUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ClearInputs destroys the caller-owned buffers, not arbitrary copies retained
// by third-party code. Inputs must never be journaled or formatted as protobuf.
func ClearInputs(inputs []Input) {
	for i := range inputs {
		clear(inputs[i].Value)
		inputs[i].Value = nil
	}
}

// TakeDelivery consumes the response's value buffers on every path. Success
// transfers ownership to the caller; failure clears all values, including those
// following the first malformed item. This helper does NOT authorize a job to
// run: composition must first commit lease acceptance, negotiate the capability
// and bind the pending request to the current stream. Recheck expiry immediately
// before launch and register redaction before output can be produced.
func TakeDelivery(job *runnerv1.JobSpecification, requestID string, message *runnerv1.GatewayMessage, now time.Time) ([]Input, time.Time, error) {
	delivery := message.GetTestSecretsDelivery()
	success := false
	defer func() {
		for _, value := range delivery.GetSecrets() {
			if value != nil {
				if !success {
					clear(value.Value)
				}
				value.Value = nil
			}
		}
	}()
	if job == nil || delivery == nil || requestID == "" || len(requestID) > 128 || delivery.GetRequestMessageId() != requestID || now.IsZero() || proto.Size(message) > MaximumDeliveryBytes || hasUnknown(message.ProtoReflect()) {
		return nil, time.Time{}, ErrUnavailable
	}
	if job.GetLease() == nil || job.GetAttempt() == nil || !proto.Equal(job.GetLease(), delivery.GetLease()) || !proto.Equal(job.GetAttempt(), delivery.GetAttempt()) ||
		delivery.GetExpiresAt() == nil || delivery.GetExpiresAt().CheckValid() != nil || job.GetLease().GetExpiresAt() == nil || job.GetLease().GetExpiresAt().CheckValid() != nil {
		return nil, time.Time{}, ErrUnavailable
	}
	expires := delivery.GetExpiresAt().AsTime()
	if !now.Before(expires) || expires.After(job.GetLease().GetExpiresAt().AsTime()) || len(job.GetTestSecrets()) < 1 || len(job.GetTestSecrets()) > MaximumFiles || len(delivery.GetSecrets()) != len(job.GetTestSecrets()) {
		return nil, time.Time{}, ErrUnavailable
	}
	previous := ""
	ids := make(map[string]bool, len(job.GetTestSecrets()))
	total := 0
	for index, ref := range job.GetTestSecrets() {
		value := delivery.GetSecrets()[index]
		if ref == nil || value == nil || !proto.Equal(ref, value.GetReference()) || !safeName.MatchString(ref.GetName()) || len(ref.GetName()) > 63 || ref.GetName() <= previous ||
			!secretUUID.MatchString(ref.GetSecretId()) || ref.GetSecretId() == "00000000-0000-0000-0000-000000000000" || ids[ref.GetSecretId()] || ref.GetVersion() < 1 || ref.GetVersion() > MaximumVersion || len(value.GetValue()) < 1 || len(value.GetValue()) > MaximumBytes || !utf8.Valid(value.GetValue()) {
			return nil, time.Time{}, ErrUnavailable
		}
		previous = ref.GetName()
		ids[ref.GetSecretId()] = true
		total += len(value.GetValue())
		if total > MaximumBytes {
			return nil, time.Time{}, ErrUnavailable
		}
	}
	inputs := make([]Input, 0, len(delivery.GetSecrets()))
	for _, value := range delivery.GetSecrets() {
		inputs = append(inputs, Input{Name: value.Reference.Name, Value: value.Value})
	}
	success = true
	return inputs, expires, nil
}

func hasUnknown(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsList() && field.Kind() == protoreflect.MessageKind {
			for i := 0; i < value.List().Len(); i++ {
				if hasUnknown(value.List().Get(i).Message()) {
					unknown = true
					break
				}
			}
		} else if field.Kind() == protoreflect.MessageKind && !field.IsMap() {
			unknown = hasUnknown(value.Message())
		}
		return !unknown
	})
	return unknown
}
