package runtimeidentity

import (
	"crypto/sha256"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

// ExecutionJobSHA256 binds every execution field while excluding only ephemeral
// object-transfer capabilities. Root and worker retain the same identity across
// capability removal/refresh; object keys, sizes, filenames and digests remain.
// This is an identity calculation, not job admission or execution permission.
func ExecutionJobSHA256(job *p.JobSpecification) ([32]byte, error) {
	if job == nil || proto.Size(job) > 1<<20 {
		return [32]byte{}, ErrUnavailable
	}
	job = proto.Clone(job).(*p.JobSpecification)
	strip := func(object *p.ObjectDownload) {
		if object != nil {
			object.Uri = ""
			object.ExpiresAt = nil
		}
	}
	strip(job.Artifact)
	for _, dependency := range job.Dependencies {
		if dependency != nil {
			strip(dependency.Object)
		}
	}
	if job.CompleteLogUpload != nil {
		job.CompleteLogUpload.Uri = ""
		job.CompleteLogUpload.ExpiresAt = nil
	}
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(job)
	if err != nil {
		return [32]byte{}, ErrUnavailable
	}
	return sha256.Sum256(raw), nil
}
