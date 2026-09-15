package paper

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestMeasuredServiceRequestProjectsTransferCapabilities(t *testing.T) {
	source, manifest, job := measuredPlanFixture(t)
	job.Artifact.Uri = "https://object.example/?synthetic-download-capability"
	job.Dependencies[0].Object.Uri = "https://object.example/?synthetic-dependency-capability"
	job.CompleteLogUpload = &p.ObjectUpload{Uri: "https://object.example/?synthetic-upload-capability", ObjectKey: "data/logs/exact.gz", ContentType: "application/gzip", ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}
	before := proto.Clone(job)
	raw, err := EncodeMeasuredRequest(job, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(before, job) || bytes.Contains(raw, []byte("synthetic-download-capability")) || bytes.Contains(raw, []byte("synthetic-dependency-capability")) || bytes.Contains(raw, []byte("synthetic-upload-capability")) {
		t.Fatal("request leaked transfer capability or mutated source")
	}
	decoded, signed, err := DecodeMeasuredRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	originalBinding, err := runtimeidentity.ExecutionJobSHA256(job)
	if err != nil {
		t.Fatal(err)
	}
	projectedBinding, err := runtimeidentity.ExecutionJobSHA256(decoded)
	if err != nil || originalBinding != projectedBinding {
		t.Fatal("worker and root execution bindings disagree", err)
	}
	if decoded.Artifact.Uri != "" || decoded.Artifact.ExpiresAt != nil || decoded.Dependencies[0].Object.Uri != "" || decoded.CompleteLogUpload.Uri != "" || decoded.CompleteLogUpload.ObjectKey != job.CompleteLogUpload.ObjectKey || !proto.Equal(decoded.Hashes, job.Hashes) || !proto.Equal(decoded.EffectivePolicy, job.EffectivePolicy) {
		t.Fatal("projected identity changed")
	}
	plan, err := source.DeriveMeasuredInputPlan(decoded, signed, 64<<30)
	if err != nil || !plan.Matches(decoded) || plan.Matches(job) {
		t.Fatal("projected signed plan binding", err)
	}
	reencoded, err := EncodeMeasuredRequest(decoded, signed)
	if err != nil || !bytes.Equal(raw, reencoded) {
		t.Fatal("request not canonical")
	}
	raw[len(raw)-1] ^= 1
	if !bytes.Equal(signed.Payload, manifest.Payload) {
		t.Fatal("mutable decoded runtime")
	}
}

func TestMeasuredServiceRequestRefusesMalformedAndCredentialBearingWire(t *testing.T) {
	_, manifest, job := measuredPlanFixture(t)
	raw, err := EncodeMeasuredRequest(job, manifest)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{"short": raw[:10], "truncated": raw[:len(raw)-1], "trailing": append(append([]byte(nil), raw...), 1), "magic": append([]byte("NOPE"), raw[4:]...)}
	bad := append([]byte(nil), raw...)
	binary.BigEndian.PutUint32(bad[4:8], 0xffffffff)
	cases["length"] = bad
	// Encoding original credential-bearing protobuf directly is not accepted as
	// an alternate wire form. Projection is a required root-side check too.
	original, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(job)
	bad = append([]byte(nil), raw[:measuredRequestHeader]...)
	binary.BigEndian.PutUint32(bad[4:8], uint32(len(original)))
	bad = append(bad, original...)
	bad = append(bad, manifest.Payload...)
	cases["capability"] = bad
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if j, m, err := DecodeMeasuredRequest(raw); err == nil || j != nil || len(m.Payload) != 0 {
				t.Fatal("invalid request admitted")
			}
		})
	}
	job.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 1})
	if _, err := ProjectMeasuredJob(job); err == nil {
		t.Fatal("unknown job fields dropped")
	}
	if _, err := EncodeMeasuredRequest(nil, manifest); err == nil {
		t.Fatal("nil job admitted")
	}
}
