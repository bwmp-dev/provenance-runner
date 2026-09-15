//go:build linux

package paper

import (
	"bytes"
	"context"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/guestoutput"
)

func TestMeasuredGuestProbeChannelPreservesPaperValidation(t *testing.T) {
	for _, valid := range []bool{true, false} {
		collector, err := evidence.NewCollector(evidence.Config{})
		if err != nil {
			t.Fatal(err)
		}
		defer collector.Close()
		var raw bytes.Buffer
		encoder := guestoutput.NewEncoder(&raw)
		for index, event := range happyProbeOutput().StructuredEvents {
			payload := event.Payload
			if !valid && index == 0 {
				payload = []byte(`{"synthetic":true}`)
			}
			if err := encoder.Write(guestoutput.Events, append(append([]byte(nil), payload...), '\n')); err != nil {
				t.Fatal(err)
			}
		}
		if err := encoder.Write(guestoutput.Outcome, []byte(`{"exitCode":0,"infrastructureFailure":false}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := collector.ConsumeGuest(context.Background(), &raw, 1024); err != nil {
			t.Fatal(err)
		}
		session := &measuredWorkerSession{collector: collector}
		output, err := session.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if output.CompleteLog != nil && output.CompleteLog.Archive != nil {
			defer output.CompleteLog.Archive.Close()
		}
		if output.MeasuredNetwork != nil {
			t.Fatal("probe payload manufactured runtime authority")
		}
		_, err = validateProbeLifecycleVersion(output, testPlan{TargetPlugin: "SuccessFixture", RequiredDependencies: []string{"DependencyFixture"}}, true)
		if (err == nil) != valid {
			t.Fatalf("valid=%t: %v", valid, err)
		}
	}
}

func TestMeasuredProjectionDoesNotCoerceOtherChannels(t *testing.T) {
	collector, err := evidence.NewCollector(evidence.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	if collector.RecordEvent(context.Background(), evidence.EventInput{Kind: "untrusted_other_channel", Payload: []byte(`{}`)}) != nil {
		t.Fatal("fixture event")
	}
	output, err := (&measuredWorkerSession{collector: collector}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if output.CompleteLog != nil && output.CompleteLog.Archive != nil {
		defer output.CompleteLog.Archive.Close()
	}
	if len(output.StructuredEvents) != 1 || output.StructuredEvents[0].Kind != "untrusted_other_channel" {
		t.Fatal("unrelated channel coerced into Paper")
	}
	if _, err := validateProbeLifecycle(output, testPlan{}); err == nil {
		t.Fatal("unrelated channel admitted")
	}
}
