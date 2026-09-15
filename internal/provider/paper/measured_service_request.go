package paper

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

const measuredRequestHeader = 12 + ed25519.SignatureSize
const MaximumMeasuredRequestBytes = measuredRequestHeader + (1 << 20) + (64 << 10)

// ProjectMeasuredJob copies the immutable execution specification while removing
// object-transfer capabilities. The credentialed worker retains the original
// downloads/uploads; root derives its input plan from this projection. Object
// hashes, keys, policy, correlation, attempt and test-secret metadata remain.
// This does not validate the job or authorize execution.
func ProjectMeasuredJob(job *p.JobSpecification) (*p.JobSpecification, error) {
	if job == nil || proto.Size(job) > maximumNormalizedConfigurationBytes || !closedMeasuredMessage(job.ProtoReflect()) {
		return nil, ErrMeasuredInputPlan
	}
	projected := proto.Clone(job).(*p.JobSpecification)
	strip := func(object *p.ObjectDownload) {
		if object != nil {
			object.Uri = ""
			object.ExpiresAt = nil
		}
	}
	strip(projected.Artifact)
	for _, dependency := range projected.Dependencies {
		if dependency != nil {
			strip(dependency.Object)
		}
	}
	if projected.CompleteLogUpload != nil {
		projected.CompleteLogUpload.Uri = ""
		projected.CompleteLogUpload.ExpiresAt = nil
	}
	return projected, nil
}

// EncodeMeasuredRequest carries only projected job metadata and the signed
// runtime. File descriptors travel separately in derived input-role order.
// No command, host path, identity override, token or test-secret value is added.
func EncodeMeasuredRequest(job *p.JobSpecification, manifest SignedRuntime) ([]byte, error) {
	projected, err := ProjectMeasuredJob(job)
	if err != nil || len(manifest.Payload) == 0 || len(manifest.Payload) > 64<<10 || len(manifest.Signature) != ed25519.SignatureSize {
		return nil, ErrMeasuredInputPlan
	}
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(projected)
	if err != nil || len(raw) == 0 || len(raw) > maximumNormalizedConfigurationBytes {
		return nil, ErrMeasuredInputPlan
	}
	result := make([]byte, measuredRequestHeader+len(raw)+len(manifest.Payload))
	copy(result, "PVP1")
	binary.BigEndian.PutUint32(result[4:8], uint32(len(raw)))
	binary.BigEndian.PutUint32(result[8:12], uint32(len(manifest.Payload)))
	copy(result[12:measuredRequestHeader], manifest.Signature)
	copy(result[measuredRequestHeader:], raw)
	copy(result[measuredRequestHeader+len(raw):], manifest.Payload)
	return result, nil
}

// DecodeMeasuredRequest performs bounded canonical decoding, not signature or
// policy admission. Root must derive the signed plan with its provisioned key,
// verify every descriptor, enforce local ceilings and obtain fresh authority.
func DecodeMeasuredRequest(raw []byte) (*p.JobSpecification, SignedRuntime, error) {
	fail := func() (*p.JobSpecification, SignedRuntime, error) { return nil, SignedRuntime{}, ErrMeasuredInputPlan }
	if len(raw) < measuredRequestHeader || len(raw) > MaximumMeasuredRequestBytes || string(raw[:4]) != "PVP1" {
		return fail()
	}
	jobSize, runtimeSize := int(binary.BigEndian.Uint32(raw[4:8])), int(binary.BigEndian.Uint32(raw[8:12]))
	if jobSize < 1 || jobSize > maximumNormalizedConfigurationBytes || runtimeSize < 1 || runtimeSize > 64<<10 || measuredRequestHeader+jobSize+runtimeSize != len(raw) {
		return fail()
	}
	job := new(p.JobSpecification)
	encoded := raw[measuredRequestHeader : measuredRequestHeader+jobSize]
	if (proto.UnmarshalOptions{RecursionLimit: 64}).Unmarshal(encoded, job) != nil {
		return fail()
	}
	projected, err := ProjectMeasuredJob(job)
	if err != nil || !proto.Equal(job, projected) {
		return fail()
	}
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(job)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return fail()
	}
	return job, SignedRuntime{Payload: append([]byte(nil), raw[measuredRequestHeader+jobSize:]...), Signature: append([]byte(nil), raw[12:measuredRequestHeader]...)}, nil
}
