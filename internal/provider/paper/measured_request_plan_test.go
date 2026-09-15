package paper

import (
	"bytes"
	"testing"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

func TestMeasuredRequestPlanVerifiesAndCopies(t *testing.T) {
	source, manifest, job := measuredPlanFixture(t)
	source.Client = nil
	raw, err := EncodeMeasuredRequest(job, manifest)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := source.PrepareMeasuredRequest(raw, 64<<30)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Job().Artifact.Uri != "" || len(plan.Inputs()) != 7 || len(plan.GuestConfiguration()) == 0 {
		t.Fatal("incomplete root plan")
	}
	copy := plan.Job()
	copy.TargetPluginName = "changed"
	inputs := plan.Inputs()
	inputs[0].Name = "changed"
	configuration := plan.GuestConfiguration()
	configuration[0] ^= 1
	if plan.Job().TargetPluginName == "changed" || plan.Inputs()[0].Name == "changed" || bytes.Equal(configuration, plan.GuestConfiguration()) {
		t.Fatal("mutable root plan")
	}
	raw[len(raw)-1] ^= 1
	if value, err := source.PrepareMeasuredRequest(raw, 64<<30); value != nil || err == nil {
		t.Fatal("unsigned altered runtime admitted")
	}
}

func TestMeasuredRequestPlanDoesNotSilentlyDropSecrets(t *testing.T) {
	source, manifest, job := measuredPlanFixture(t)
	job.TestSecrets = []*p.TestSecretReference{{}}
	raw, err := EncodeMeasuredRequest(job, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if plan, err := source.PrepareMeasuredRequest(raw, 64<<30); plan != nil || err == nil {
		t.Fatal("missing secret injection bypassed")
	}
}
