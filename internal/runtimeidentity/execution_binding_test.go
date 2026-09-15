package runtimeidentity

import (
	"testing"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestExecutionBindingExcludesOnlyTransferCapabilities(t *testing.T) {
	job := &p.JobSpecification{TargetPluginName: "Target", Artifact: &p.ObjectDownload{Uri: "https://object.example/?synthetic-a", ExpiresAt: timestamppb.New(time.Now()), Filename: "target.jar", SizeBytes: 1}, Dependencies: []*p.DependencyInput{{DependencyId: "dependency", Object: &p.ObjectDownload{Uri: "https://object.example/?synthetic-b", ExpiresAt: timestamppb.New(time.Now()), Filename: "dependency.jar", SizeBytes: 2}}}, CompleteLogUpload: &p.ObjectUpload{Uri: "https://object.example/?synthetic-c", ExpiresAt: timestamppb.New(time.Now()), ObjectKey: "data/log.gz"}}
	before := proto.Clone(job)
	hash, err := ExecutionJobSHA256(job)
	if err != nil || !proto.Equal(before, job) {
		t.Fatal("binding mutated source", err)
	}
	projected := proto.Clone(job).(*p.JobSpecification)
	projected.Artifact.Uri = ""
	projected.Artifact.ExpiresAt = nil
	projected.Dependencies[0].Object.Uri = ""
	projected.Dependencies[0].Object.ExpiresAt = nil
	projected.CompleteLogUpload.Uri = ""
	projected.CompleteLogUpload.ExpiresAt = nil
	if actual, err := ExecutionJobSHA256(projected); err != nil || actual != hash {
		t.Fatal("projection changed execution identity")
	}
	for _, mutate := range []func(*p.JobSpecification){func(j *p.JobSpecification) { j.TargetPluginName = "Other" }, func(j *p.JobSpecification) { j.Artifact.SizeBytes++ }, func(j *p.JobSpecification) { j.Dependencies[0].Object.Filename = "other.jar" }, func(j *p.JobSpecification) { j.CompleteLogUpload.ObjectKey = "data/other.gz" }} {
		changed := proto.Clone(job).(*p.JobSpecification)
		mutate(changed)
		if actual, err := ExecutionJobSHA256(changed); err != nil || actual == hash {
			t.Fatal("execution field lost from binding", err)
		}
	}
	if _, err := ExecutionJobSHA256(&p.JobSpecification{NormalizedConfigurationJson: make([]byte, 1<<20)}); err == nil {
		t.Fatal("oversized binding accepted")
	}
}
