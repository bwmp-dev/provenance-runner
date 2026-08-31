package paper

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

func TestProbeLifecycleProducesAuthoritativeStructuredEvents(t *testing.T) {
	events, err := validateProbeLifecycle(happyProbeOutput(), testPlan{TargetPlugin: "SuccessFixture", RequiredDependencies: []string{"DependencyFixture"}})
	if err != nil {
		t.Fatalf("validateProbeLifecycle() error = %v", err)
	}
	if len(events) != 9 || events[0].Kind != "PROBE_LOADED" || events[len(events)-1].Kind != "SERVER_STOPPED" {
		t.Fatalf("events = %#v", events)
	}
	if strings.Contains(string(events[0].Payload), "timestamp") {
		t.Errorf("event payload retained transport envelope: %s", events[0].Payload)
	}
}

func TestProbeLifecycleRejectsMissingMalformedDuplicateAndOutOfOrderEvents(t *testing.T) {
	base := happyProbeOutput()
	tests := map[string]func(*execution.CollectedOutput){
		"missing": func(output *execution.CollectedOutput) {
			output.StructuredEvents = output.StructuredEvents[:len(output.StructuredEvents)-1]
		},
		"malformed": func(output *execution.CollectedOutput) {
			output.StructuredEvents[0].Payload = json.RawMessage(`{"timestamp":`)
		},
		"unknown type": func(output *execution.CollectedOutput) {
			output.StructuredEvents[0] = probeStructuredEvent(1, "INJECTED_EVENT", `{}`)
		},
		"channel error": func(output *execution.CollectedOutput) {
			output.StructuredEventError = "invalid JSON"
		},
		"duplicate": func(output *execution.CollectedOutput) {
			output.StructuredEvents = append(output.StructuredEvents, output.StructuredEvents[len(output.StructuredEvents)-1])
		},
		"out of order": func(output *execution.CollectedOutput) {
			output.StructuredEvents[0], output.StructuredEvents[1] = output.StructuredEvents[1], output.StructuredEvents[0]
		},
		"truncated": func(output *execution.CollectedOutput) {
			output.EvidenceUsage.EventsTruncated = true
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			output := base
			output.StructuredEvents = append([]execution.StructuredEvent(nil), base.StructuredEvents...)
			mutate(&output)
			if _, err := validateProbeLifecycle(output, testPlan{TargetPlugin: "SuccessFixture", RequiredDependencies: []string{"DependencyFixture"}}); err == nil {
				t.Fatal("validateProbeLifecycle() error = nil")
			}
		})
	}
}

func TestProbeLifecycleRejectsTerminalAssertionsAndFailureEvents(t *testing.T) {
	for name, mutate := range map[string]func(*execution.CollectedOutput){
		"failed requirement": func(output *execution.CollectedOutput) {
			output.StructuredEvents[3] = probeStructuredEvent(4, "TARGET_REQUIREMENT", `{"name":"SuccessFixture","configured":true,"loaded":true,"enabled":false}`)
		},
		"classification": func(output *execution.CollectedOutput) {
			failure := probeStructuredEvent(4, "CLASSIFICATION", `{"code":"on_enable_failure"}`)
			output.StructuredEvents = append(output.StructuredEvents[:3], append([]execution.StructuredEvent{failure}, output.StructuredEvents[3:]...)...)
		},
		"lifecycle exception": func(output *execution.CollectedOutput) {
			failure := probeStructuredEvent(4, "LIFECYCLE_EXCEPTION", `{}`)
			output.StructuredEvents = append(output.StructuredEvents[:3], append([]execution.StructuredEvent{failure}, output.StructuredEvents[3:]...)...)
		},
		"server ready false": func(output *execution.CollectedOutput) {
			output.StructuredEvents[6] = probeStructuredEvent(7, "SERVER_READY", `{"requirementsSatisfied":false}`)
		},
		"unclean stop": func(output *execution.CollectedOutput) {
			output.StructuredEvents[8] = probeStructuredEvent(9, "SERVER_STOPPED", `{"shutdownRequested":false}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			output := happyProbeOutput()
			mutate(&output)
			if _, err := validateProbeLifecycle(output, testPlan{TargetPlugin: "SuccessFixture", RequiredDependencies: []string{"DependencyFixture"}}); err == nil {
				t.Fatal("validateProbeLifecycle() error = nil")
			}
		})
	}
}
