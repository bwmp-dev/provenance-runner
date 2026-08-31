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
	if len(events) != 10 || events[0].Kind != "TEST_PLAN" || events[1].Kind != "PROBE_LOADED" || events[len(events)-1].Kind != "SERVER_STOPPED" {
		t.Fatalf("events = %#v", events)
	}
	if strings.Contains(string(events[1].Payload), "timestamp") {
		t.Errorf("event payload retained transport envelope: %s", events[1].Payload)
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
			output.StructuredEvents[1], output.StructuredEvents[2] = output.StructuredEvents[2], output.StructuredEvents[1]
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
			replaceProbeEvent(t, output, "TARGET_REQUIREMENT", `{"name":"SuccessFixture","configured":true,"loaded":true,"enabled":false}`)
		},
		"classification": func(output *execution.CollectedOutput) {
			failure := probeStructuredEvent(5, "CLASSIFICATION", `{"code":"on_enable_failure"}`)
			output.StructuredEvents = append(output.StructuredEvents[:4], append([]execution.StructuredEvent{failure}, output.StructuredEvents[4:]...)...)
		},
		"lifecycle exception": func(output *execution.CollectedOutput) {
			failure := probeStructuredEvent(5, "LIFECYCLE_EXCEPTION", `{}`)
			output.StructuredEvents = append(output.StructuredEvents[:4], append([]execution.StructuredEvent{failure}, output.StructuredEvents[4:]...)...)
		},
		"server ready false": func(output *execution.CollectedOutput) {
			replaceProbeEvent(t, output, "SERVER_READY", `{"requirementsSatisfied":false}`)
		},
		"unclean stop": func(output *execution.CollectedOutput) {
			replaceProbeEvent(t, output, "SERVER_STOPPED", `{"shutdownRequested":false}`)
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

func TestProbeLifecycleMapsCompletedCommandEvents(t *testing.T) {
	plan := testPlan{TargetPlugin: "SuccessFixture", Console: []consoleCommandTest{{ID: "version-command"}}}
	events, err := validateProbeLifecycle(commandProbeOutput(true), plan)
	if err != nil {
		t.Fatalf("validateProbeLifecycle() error = %v", err)
	}
	var kinds []string
	for _, event := range events {
		kinds = append(kinds, event.Kind)
	}
	for _, expected := range []string{"COMMAND_REGISTRATION", "COMMAND_OUTPUT", "COMMAND_ASSERTION", "COMMAND_TEST_COMPLETED"} {
		if !contains(kinds, expected) {
			t.Errorf("structured event kinds %v do not contain %s", kinds, expected)
		}
	}
}

func TestProbeLifecycleRejectsCommandFailureUnknownClassificationAndMissingCompletion(t *testing.T) {
	plan := testPlan{TargetPlugin: "SuccessFixture", Console: []consoleCommandTest{{ID: "version-command"}}}

	failed := commandProbeOutput(false)
	if _, err := validateProbeLifecycle(failed, plan); err == nil || !strings.Contains(err.Error(), "command") {
		t.Fatalf("failed command error = %v", err)
	}

	unknownClassification := commandProbeOutput(true)
	classification := probeStructuredEvent(13, "CLASSIFICATION", `{"code":"new_unreviewed_failure"}`)
	unknownClassification.StructuredEvents = append(unknownClassification.StructuredEvents[:12], append([]execution.StructuredEvent{classification}, unknownClassification.StructuredEvents[12:]...)...)
	if _, err := validateProbeLifecycle(unknownClassification, plan); err == nil || !strings.Contains(err.Error(), "unsupported code") {
		t.Fatalf("unknown classification error = %v", err)
	}

	missingCompletion := commandProbeOutput(true)
	for index, event := range missingCompletion.StructuredEvents {
		envelope, _ := decodeProbeEnvelope(event.Payload)
		if envelope.Type == "COMMAND_TEST_COMPLETED" {
			missingCompletion.StructuredEvents = append(missingCompletion.StructuredEvents[:index], missingCompletion.StructuredEvents[index+1:]...)
			break
		}
	}
	if _, err := validateProbeLifecycle(missingCompletion, plan); err == nil || !strings.Contains(err.Error(), "missing command completion") {
		t.Fatalf("missing command completion error = %v", err)
	}
}

func commandProbeOutput(passed bool) execution.CollectedOutput {
	assertion := `{"testId":"version-command","assertionId":"version-command:1","evaluated":true,"passed":true}`
	completion := `{"testId":"version-command","passed":true}`
	planCompletion := `{"status":"COMPLETED","consoleTests":1,"passed":true,"timedOut":false}`
	events := []execution.StructuredEvent{
		probeStructuredEvent(1, "TEST_PLAN", `{"status":"LOADED","consoleTests":1,"maximumCommandOutputBytes":4096}`),
		probeStructuredEvent(2, "PROBE_LOADED", `{}`),
		probeStructuredEvent(3, "SERVER_LOADED", `{}`),
		probeStructuredEvent(4, "STABILIZATION_STARTED", `{}`),
		probeStructuredEvent(5, "TARGET_REQUIREMENT", `{"name":"SuccessFixture","configured":true,"loaded":true,"enabled":true}`),
		probeStructuredEvent(6, "STABILIZATION_COMPLETED", `{}`),
		probeStructuredEvent(7, "SERVER_READY", `{"requirementsSatisfied":true}`),
		probeStructuredEvent(8, "COMMAND_REGISTRATION", `{"testId":"version-command","registered":true,"status":"REGISTERED"}`),
		probeStructuredEvent(9, "COMMAND_EXECUTION_STARTED", `{"testId":"version-command","timeoutSeconds":10}`),
		probeStructuredEvent(10, "COMMAND_OUTPUT", `{"testId":"version-command","stream":"stdout","lines":["ok"],"capturedBytes":2,"observedBytes":2,"truncated":false}`),
		probeStructuredEvent(11, "COMMAND_EXECUTION_COMPLETED", `{"testId":"version-command","status":"COMPLETED","dispatched":true}`),
		probeStructuredEvent(12, "COMMAND_ASSERTION", assertion),
		probeStructuredEvent(13, "COMMAND_TEST_COMPLETED", completion),
		probeStructuredEvent(14, "TEST_PLAN", planCompletion),
		probeStructuredEvent(15, "CLEAN_SHUTDOWN_REQUESTED", `{}`),
		probeStructuredEvent(16, "SERVER_STOPPED", `{"shutdownRequested":true}`),
	}
	if !passed {
		events[11] = probeStructuredEvent(12, "COMMAND_ASSERTION", `{"testId":"version-command","assertionId":"version-command:1","evaluated":true,"passed":false}`)
		classification := probeStructuredEvent(13, "CLASSIFICATION", `{"code":"command_assertion_failure"}`)
		events = append(events[:12], append([]execution.StructuredEvent{classification}, events[12:]...)...)
		events[13] = probeStructuredEvent(14, "COMMAND_TEST_COMPLETED", `{"testId":"version-command","passed":false}`)
		events[14] = probeStructuredEvent(15, "TEST_PLAN", `{"status":"COMPLETED","consoleTests":1,"passed":false,"timedOut":false}`)
	}
	var eventBytes int64
	for _, event := range events {
		eventBytes += int64(len(event.Payload))
	}
	return execution.CollectedOutput{StructuredEvents: events, EvidenceUsage: execution.EvidenceUsage{StructuredEventCount: int64(len(events)), StructuredEventBytes: eventBytes}}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func replaceProbeEvent(t *testing.T, output *execution.CollectedOutput, eventType, data string) {
	t.Helper()
	for index, event := range output.StructuredEvents {
		envelope, err := decodeProbeEnvelope(event.Payload)
		if err == nil && envelope.Type == eventType {
			output.StructuredEvents[index] = probeStructuredEvent(event.Sequence, eventType, data)
			return
		}
	}
	t.Fatalf("event %s not found", eventType)
}
