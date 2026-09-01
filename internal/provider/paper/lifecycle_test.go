package paper

import (
	"encoding/json"
	"errors"
	"fmt"
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
			replaceProbeEvent(t, output, "TARGET_REQUIREMENT", `{"role":"TARGET","name":"SuccessFixture","configured":true,"loaded":true,"enabled":false}`)
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

func TestProbeLifecyclePreservesValidatedBenignFailureClassifications(t *testing.T) {
	for _, test := range []struct {
		name   string
		code   string
		mutate func(*execution.CollectedOutput)
	}{
		{
			name: "on load failure",
			code: "on_load_failure",
			mutate: func(output *execution.CollectedOutput) {
				failure := []execution.StructuredEvent{
					probeStructuredEvent(5, "LIFECYCLE_EXCEPTION", `{"phase":"LOAD","plugin":"SuccessFixture"}`),
					probeStructuredEvent(6, "CLASSIFICATION", `{"code":"on_load_failure","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_STARTUP","retryable":false,"plugin":"SuccessFixture"}`),
				}
				output.StructuredEvents = append(output.StructuredEvents[:4], append(failure, output.StructuredEvents[4:]...)...)
			},
		},
		{
			name: "on enable failure",
			code: "on_enable_failure",
			mutate: func(output *execution.CollectedOutput) {
				failure := []execution.StructuredEvent{
					probeStructuredEvent(5, "LIFECYCLE_EXCEPTION", `{"phase":"ENABLE","plugin":"SuccessFixture"}`),
					probeStructuredEvent(6, "CLASSIFICATION", `{"code":"on_enable_failure","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_STARTUP","retryable":false,"plugin":"SuccessFixture"}`),
				}
				output.StructuredEvents = append(output.StructuredEvents[:4], append(failure, output.StructuredEvents[4:]...)...)
				replaceProbeEvent(t, output, "TARGET_REQUIREMENT", `{"role":"TARGET","name":"SuccessFixture","configured":true,"loaded":true,"enabled":false}`)
				replaceProbeEvent(t, output, "SERVER_READY", `{"requirementsSatisfied":false}`)
			},
		},
		{
			name: "missing dependency",
			code: "missing_required_dependency",
			mutate: func(output *execution.CollectedOutput) {
				for index, event := range output.StructuredEvents {
					envelope, _ := decodeProbeEnvelope(event.Payload)
					if envelope.Type == "TARGET_REQUIREMENT" && strings.Contains(string(envelope.Data), "DependencyFixture") {
						output.StructuredEvents[index] = probeStructuredEvent(event.Sequence, "TARGET_REQUIREMENT", `{"role":"REQUIRED_DEPENDENCY","name":"DependencyFixture","configured":true,"loaded":false,"enabled":false}`)
						classification := probeStructuredEvent(7, "CLASSIFICATION", `{"code":"missing_required_dependency","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_PREPARATION","retryable":false,"plugin":"DependencyFixture","role":"REQUIRED_DEPENDENCY"}`)
						output.StructuredEvents = append(output.StructuredEvents[:index+1], append([]execution.StructuredEvent{classification}, output.StructuredEvents[index+1:]...)...)
						break
					}
				}
				replaceProbeEvent(t, output, "SERVER_READY", `{"requirementsSatisfied":false}`)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := happyProbeOutput()
			test.mutate(&output)
			_, err := validateProbeLifecycle(output, testPlan{TargetPlugin: "SuccessFixture", RequiredDependencies: []string{"DependencyFixture"}})
			var classified *probeLifecycleFailure
			if !errors.As(err, &classified) || classified.code != test.code {
				t.Fatalf("validateProbeLifecycle() error = %#v, want code %q", err, test.code)
			}
		})
	}
}

func TestProbeLifecycleDoesNotTrustMalformedForgedOrConflictingClassification(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*execution.CollectedOutput)
	}{
		{
			name: "forged category",
			mutate: func(output *execution.CollectedOutput) {
				failure := []execution.StructuredEvent{
					probeStructuredEvent(5, "LIFECYCLE_EXCEPTION", `{"phase":"LOAD","plugin":"SuccessFixture"}`),
					probeStructuredEvent(6, "CLASSIFICATION", `{"code":"on_load_failure","category":"FAILURE_CATEGORY_INFRASTRUCTURE","stage":"FAILURE_STAGE_STARTUP","retryable":false,"plugin":"SuccessFixture"}`),
				}
				output.StructuredEvents = append(output.StructuredEvents[:4], append(failure, output.StructuredEvents[4:]...)...)
			},
		},
		{
			name: "forged without evidence",
			mutate: func(output *execution.CollectedOutput) {
				classification := probeStructuredEvent(5, "CLASSIFICATION", `{"code":"on_load_failure","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_STARTUP","retryable":false,"plugin":"SuccessFixture"}`)
				output.StructuredEvents = append(output.StructuredEvents[:4], append([]execution.StructuredEvent{classification}, output.StructuredEvents[4:]...)...)
			},
		},
		{
			name: "conflicting classifications",
			mutate: func(output *execution.CollectedOutput) {
				failure := []execution.StructuredEvent{
					probeStructuredEvent(5, "LIFECYCLE_EXCEPTION", `{"phase":"LOAD","plugin":"SuccessFixture"}`),
					probeStructuredEvent(6, "CLASSIFICATION", `{"code":"on_load_failure","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_STARTUP","retryable":false,"plugin":"SuccessFixture"}`),
					probeStructuredEvent(7, "LIFECYCLE_EXCEPTION", `{"phase":"ENABLE","plugin":"SuccessFixture"}`),
					probeStructuredEvent(8, "CLASSIFICATION", `{"code":"on_enable_failure","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_STARTUP","retryable":false,"plugin":"SuccessFixture"}`),
				}
				output.StructuredEvents = append(output.StructuredEvents[:4], append(failure, output.StructuredEvents[4:]...)...)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := happyProbeOutput()
			test.mutate(&output)
			_, err := validateProbeLifecycle(output, testPlan{TargetPlugin: "SuccessFixture", RequiredDependencies: []string{"DependencyFixture"}})
			if err == nil {
				t.Fatal("validateProbeLifecycle() error = nil")
			}
			var classified *probeLifecycleFailure
			if errors.As(err, &classified) {
				t.Fatalf("untrusted classification escaped as %q: %v", classified.code, err)
			}
		})
	}
}

func TestProbeLifecycleRejectsImpossibleAlphaRequirementStates(t *testing.T) {
	for _, data := range []string{
		`{"role":"TARGET","name":"SuccessFixture","configured":false,"loaded":false,"enabled":false}`,
		`{"role":"TARGET","name":"SuccessFixture","configured":true,"loaded":false,"enabled":true}`,
	} {
		t.Run(data, func(t *testing.T) {
			output := happyProbeOutput()
			replaceProbeEvent(t, &output, "TARGET_REQUIREMENT", data)
			_, err := validateProbeLifecycle(output, testPlan{TargetPlugin: "SuccessFixture", RequiredDependencies: []string{"DependencyFixture"}})
			if err == nil {
				t.Fatal("validateProbeLifecycle() error = nil")
			}
			var classified *probeLifecycleFailure
			if errors.As(err, &classified) {
				t.Fatalf("impossible requirement state escaped as %q: %v", classified.code, err)
			}
		})
	}
}

func TestProbeLifecycleRejectsRequirementCodesThatConflictWithAlphaStatus(t *testing.T) {
	for _, test := range []struct {
		name            string
		requirementName string
		code            string
		classification  string
	}{
		{
			name:            "loaded target as not found",
			requirementName: "SuccessFixture",
			code:            "plugin_not_found",
			classification:  `{"code":"plugin_not_found","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_PREPARATION","retryable":false,"plugin":"SuccessFixture","role":"TARGET"}`,
		},
		{
			name:            "loaded dependency as missing",
			requirementName: "DependencyFixture",
			code:            "missing_required_dependency",
			classification:  `{"code":"missing_required_dependency","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_PREPARATION","retryable":false,"plugin":"DependencyFixture","role":"REQUIRED_DEPENDENCY"}`,
		},
		{
			name:            "enabled dependency as failed",
			requirementName: "DependencyFixture",
			code:            "failed_required_dependency",
			classification:  `{"code":"failed_required_dependency","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_STARTUP","retryable":false,"plugin":"DependencyFixture","role":"REQUIRED_DEPENDENCY"}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := happyProbeOutput()
			inserted := false
			for index, event := range output.StructuredEvents {
				envelope, _ := decodeProbeEnvelope(event.Payload)
				if envelope.Type == "TARGET_REQUIREMENT" && strings.Contains(string(envelope.Data), test.requirementName) {
					classification := probeStructuredEvent(event.Sequence+1, "CLASSIFICATION", test.classification)
					output.StructuredEvents = append(output.StructuredEvents[:index+1], append([]execution.StructuredEvent{classification}, output.StructuredEvents[index+1:]...)...)
					inserted = true
					break
				}
			}
			if !inserted {
				t.Fatalf("requirement %q not found", test.requirementName)
			}
			_, err := validateProbeLifecycle(output, testPlan{TargetPlugin: "SuccessFixture", RequiredDependencies: []string{"DependencyFixture"}})
			if err == nil || !strings.Contains(err.Error(), "classification "+test.code+" conflicts with requirement status") {
				t.Fatalf("validateProbeLifecycle() error = %v", err)
			}
			var classified *probeLifecycleFailure
			if errors.As(err, &classified) {
				t.Fatalf("forged requirement classification escaped as %q: %v", classified.code, err)
			}
		})
	}
}

func TestProbeLifecycleMapsCompletedCommandEvents(t *testing.T) {
	plan := testPlan{TargetPlugin: "SuccessFixture", Console: []consoleCommandTest{{ID: "version-command", Assertions: []commandAssertion{{}}}}}
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

func TestProbeLifecycleAcceptsPinnedProbeOutputTruncationSequence(t *testing.T) {
	plan := testPlan{TargetPlugin: "SuccessFixture", Console: []consoleCommandTest{{ID: "version-command", Assertions: []commandAssertion{{}, {}}}}}
	output := commandProbeOutput(true)
	output.StructuredEvents[9] = probeStructuredEvent(10, "COMMAND_OUTPUT", `{"testId":"version-command","stream":"stdout","lines":["ok"],"capturedBytes":4,"observedBytes":8,"truncated":true}`)
	output.StructuredEvents[11] = probeStructuredEvent(12, "COMMAND_ASSERTION", `{"testId":"version-command","assertionId":"version-command:1","evaluated":false,"passed":false}`)
	output.StructuredEvents = append(output.StructuredEvents[:12], append([]execution.StructuredEvent{
		probeStructuredEvent(13, "COMMAND_ASSERTION", `{"testId":"version-command","assertionId":"version-command:2","evaluated":false,"passed":false}`),
		probeStructuredEvent(14, "CLASSIFICATION", `{"code":"command_output_truncated","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_EXECUTION","retryable":false,"testId":"version-command"}`),
	}, output.StructuredEvents[12:]...)...)
	output.StructuredEvents[14] = probeStructuredEvent(15, "COMMAND_TEST_COMPLETED", `{"testId":"version-command","passed":false}`)
	output.StructuredEvents[15] = probeStructuredEvent(16, "TEST_PLAN", `{"status":"COMPLETED","consoleTests":1,"passed":false,"timedOut":false}`)

	events, err := validateProbeLifecycle(output, plan)
	if err == nil {
		t.Fatal("validateProbeLifecycle() error = nil for failed command plan")
	}
	if strings.Contains(err.Error(), "out of order") || strings.Contains(err.Error(), "contradicts") {
		t.Fatalf("valid pinned truncation sequence was rejected as contradictory: %v", err)
	}
	expectedKinds := []string{
		"TEST_PLAN", "PROBE_LOADED", "SERVER_LOADED", "STABILIZATION_STARTED", "TARGET_REQUIREMENT",
		"STABILIZATION_COMPLETED", "SERVER_READY", "COMMAND_REGISTRATION", "COMMAND_EXECUTION_STARTED",
		"COMMAND_OUTPUT", "COMMAND_EXECUTION_COMPLETED", "COMMAND_ASSERTION", "COMMAND_ASSERTION",
		"CLASSIFICATION", "COMMAND_TEST_COMPLETED", "TEST_PLAN", "CLEAN_SHUTDOWN_REQUESTED", "SERVER_STOPPED",
	}
	if len(events) != len(expectedKinds) {
		t.Fatalf("mapped event count = %d, want %d (%#v)", len(events), len(expectedKinds), events)
	}
	for index, expected := range expectedKinds {
		if events[index].Kind != expected {
			t.Fatalf("mapped event %d = %s, want %s", index, events[index].Kind, expected)
		}
	}
	for _, index := range []int{11, 12} {
		if !strings.Contains(string(events[index].Payload), `"evaluated":false`) || !strings.Contains(string(events[index].Payload), `"passed":false`) {
			t.Fatalf("unevaluated truncation assertion was not preserved: %s", events[index].Payload)
		}
	}
	if !strings.Contains(string(events[13].Payload), `"code":"command_output_truncated"`) {
		t.Fatalf("stable truncation classification was not preserved: %s", events[13].Payload)
	}
}

func TestCommandProbeStateRejectsUnevaluatedAssertionsOutsideTruncation(t *testing.T) {
	for _, test := range []struct {
		name      string
		output    string
		assertion string
	}{
		{
			name:      "normal output",
			output:    `{"truncated":false,"capturedBytes":4,"observedBytes":4}`,
			assertion: `{"assertionId":"version-command:1","evaluated":false,"passed":false}`,
		},
		{
			name:      "passed unevaluated assertion after truncation",
			output:    `{"truncated":true,"capturedBytes":4,"observedBytes":8}`,
			assertion: `{"assertionId":"version-command:1","evaluated":false,"passed":true}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := newCommandProbeState(consoleCommandTest{ID: "version-command", Assertions: []commandAssertion{{}}})
			for _, event := range []struct {
				kind string
				data string
			}{
				{kind: "COMMAND_REGISTRATION", data: `{"registered":true,"status":"REGISTERED"}`},
				{kind: "COMMAND_EXECUTION_STARTED", data: `{"timeoutSeconds":1}`},
				{kind: "COMMAND_OUTPUT", data: test.output},
				{kind: "COMMAND_EXECUTION_COMPLETED", data: `{"status":"COMPLETED","dispatched":true}`},
			} {
				if err := state.accept(event.kind, json.RawMessage(event.data)); err != nil {
					t.Fatalf("accept(%s) error = %v", event.kind, err)
				}
			}
			if err := state.accept("COMMAND_ASSERTION", json.RawMessage(test.assertion)); err == nil {
				t.Fatal("unevaluated assertion unexpectedly succeeded")
			}
		})
	}
}

func TestProbeLifecycleCorrelatesTestPlanTimeout(t *testing.T) {
	plan := testPlan{TargetPlugin: "SuccessFixture", Console: []consoleCommandTest{{ID: "version-command", Assertions: []commandAssertion{{}}}}}

	noCommandTimeout := commandProbeOutput(true)
	noCommandTimeout.StructuredEvents[13] = probeStructuredEvent(14, "TEST_PLAN", `{"status":"COMPLETED","consoleTests":1,"passed":false,"timedOut":true}`)
	if _, err := validateProbeLifecycle(noCommandTimeout, plan); err == nil || !strings.Contains(err.Error(), "timedOut does not match command timeout evidence") {
		t.Fatalf("plan timeout without command timeout error = %v", err)
	}

	commandTimeout := commandProbeOutput(true)
	commandTimeout.StructuredEvents[9] = probeStructuredEvent(10, "COMMAND_TIMEOUT", `{"testId":"version-command","timeoutSeconds":10}`)
	commandTimeout.StructuredEvents[10] = probeStructuredEvent(11, "CLASSIFICATION", `{"code":"command_timeout","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_EXECUTION","retryable":false,"testId":"version-command"}`)
	commandTimeout.StructuredEvents[11] = probeStructuredEvent(12, "COMMAND_OUTPUT", `{"testId":"version-command","stream":"stdout","lines":["ok"],"capturedBytes":2,"observedBytes":2,"truncated":false}`)
	commandTimeout.StructuredEvents[12] = probeStructuredEvent(13, "COMMAND_EXECUTION_COMPLETED", `{"testId":"version-command","status":"TIMED_OUT"}`)
	commandTimeout.StructuredEvents[13] = probeStructuredEvent(14, "COMMAND_TEST_COMPLETED", `{"testId":"version-command","passed":false}`)
	commandTimeout.StructuredEvents[14] = probeStructuredEvent(15, "TEST_PLAN", `{"status":"COMPLETED","consoleTests":1,"passed":false,"timedOut":false}`)
	if _, err := validateProbeLifecycle(commandTimeout, plan); err == nil || !strings.Contains(err.Error(), "timedOut does not match command timeout evidence") {
		t.Fatalf("command timeout without plan timeout error = %v", err)
	}

	consistentTimeout := commandProbeOutput(true)
	consistentTimeout.StructuredEvents[9] = probeStructuredEvent(10, "COMMAND_TIMEOUT", `{"testId":"version-command","timeoutSeconds":10}`)
	consistentTimeout.StructuredEvents[10] = probeStructuredEvent(11, "CLASSIFICATION", `{"code":"command_timeout","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_EXECUTION","retryable":false,"testId":"version-command"}`)
	consistentTimeout.StructuredEvents[11] = probeStructuredEvent(12, "COMMAND_OUTPUT", `{"testId":"version-command","stream":"stdout","lines":["ok"],"capturedBytes":2,"observedBytes":2,"truncated":false}`)
	consistentTimeout.StructuredEvents[12] = probeStructuredEvent(13, "COMMAND_EXECUTION_COMPLETED", `{"testId":"version-command","status":"TIMED_OUT"}`)
	consistentTimeout.StructuredEvents[13] = probeStructuredEvent(14, "COMMAND_TEST_COMPLETED", `{"testId":"version-command","passed":false}`)
	consistentTimeout.StructuredEvents[14] = probeStructuredEvent(15, "TEST_PLAN", `{"status":"COMPLETED","consoleTests":1,"passed":false,"timedOut":true}`)
	if _, err := validateProbeLifecycle(consistentTimeout, plan); err == nil || strings.Contains(err.Error(), "timedOut does not match") {
		t.Fatalf("consistent command/plan timeout error = %v", err)
	}

	contradictory := commandProbeOutput(true)
	contradictory.StructuredEvents[13] = probeStructuredEvent(14, "TEST_PLAN", `{"status":"COMPLETED","consoleTests":1,"passed":true,"timedOut":true}`)
	if _, err := validateProbeLifecycle(contradictory, plan); err == nil || !strings.Contains(err.Error(), "both passed and timed out") {
		t.Fatalf("contradictory plan timeout error = %v", err)
	}
}

func TestProbeLifecycleAcceptsPinnedMultiCommandTimeout(t *testing.T) {
	plan := testPlan{TargetPlugin: "SuccessFixture", Console: []consoleCommandTest{
		{ID: "first-command", Assertions: []commandAssertion{{}}},
		{ID: "second-command", Assertions: []commandAssertion{{}}},
	}}

	events, err := validateProbeLifecycle(pinnedMultiCommandTimeoutOutput(), plan)
	if err == nil {
		t.Fatal("validateProbeLifecycle() error = nil for timed-out command plan")
	}
	if strings.Contains(err.Error(), "missing command completion") || strings.Contains(err.Error(), "second-command") {
		t.Fatalf("untouched trailing command was treated as incomplete: %v", err)
	}
	expectedKinds := []string{
		"TEST_PLAN", "PROBE_LOADED", "SERVER_LOADED", "STABILIZATION_STARTED", "TARGET_REQUIREMENT",
		"STABILIZATION_COMPLETED", "SERVER_READY", "COMMAND_REGISTRATION", "COMMAND_EXECUTION_STARTED",
		"COMMAND_TIMEOUT", "CLASSIFICATION", "COMMAND_OUTPUT", "COMMAND_EXECUTION_COMPLETED", "COMMAND_TEST_COMPLETED",
		"TEST_PLAN", "CLEAN_SHUTDOWN_REQUESTED", "SERVER_STOPPED",
	}
	if len(events) != len(expectedKinds) {
		t.Fatalf("mapped event count = %d, want %d", len(events), len(expectedKinds))
	}
	for index, expected := range expectedKinds {
		if events[index].Kind != expected {
			t.Fatalf("mapped event %d = %s, want %s", index, events[index].Kind, expected)
		}
	}
	if !strings.Contains(string(events[10].Payload), `"code":"command_timeout"`) {
		t.Fatalf("timeout classification was not preserved: %s", events[10].Payload)
	}
	if !strings.Contains(string(events[11].Payload), `"capturedBytes":7`) || !strings.Contains(string(events[11].Payload), `"observedBytes":7`) {
		t.Fatalf("timeout output was not preserved: %s", events[11].Payload)
	}
}

func TestProbeLifecycleRejectsCommandEventsAroundPinnedTimeout(t *testing.T) {
	plan := testPlan{TargetPlugin: "SuccessFixture", Console: []consoleCommandTest{
		{ID: "first-command", Assertions: []commandAssertion{{}}},
		{ID: "second-command", Assertions: []commandAssertion{{}}},
	}}
	tests := []struct {
		name      string
		mutate    func([]execution.StructuredEvent) []execution.StructuredEvent
		expectErr string
	}{
		{
			name: "gap before timeout",
			mutate: func(events []execution.StructuredEvent) []execution.StructuredEvent {
				return insertProbeEvent(events, 8, probeStructuredEvent(9, "COMMAND_REGISTRATION", `{"testId":"second-command","registered":true,"status":"REGISTERED"}`))
			},
			expectErr: "skips configured command",
		},
		{
			name: "later command after timeout",
			mutate: func(events []execution.StructuredEvent) []execution.StructuredEvent {
				return insertProbeEvent(events, 14, probeStructuredEvent(14, "COMMAND_REGISTRATION", `{"testId":"second-command","registered":true,"status":"REGISTERED"}`))
			},
			expectErr: "after a timed-out command",
		},
		{
			name: "missing timeout classification",
			mutate: func(events []execution.StructuredEvent) []execution.StructuredEvent {
				return removeProbeEvent(events, "CLASSIFICATION", "first-command")
			},
			expectErr: "missing its timeout classification",
		},
		{
			name: "timeout classification after output",
			mutate: func(events []execution.StructuredEvent) []execution.StructuredEvent {
				events[10], events[11] = events[11], events[10]
				return events
			},
			expectErr: "missing its timeout classification",
		},
		{
			name: "missing timeout output",
			mutate: func(events []execution.StructuredEvent) []execution.StructuredEvent {
				return removeProbeEvent(events, "COMMAND_OUTPUT", "first-command")
			},
			expectErr: "incomplete timeout trace",
		},
		{
			name: "execution completion before timed-out completion",
			mutate: func(events []execution.StructuredEvent) []execution.StructuredEvent {
				events[12], events[13] = events[13], events[12]
				return events
			},
			expectErr: "after its completion",
		},
		{
			name: "missing execution completion",
			mutate: func(events []execution.StructuredEvent) []execution.StructuredEvent {
				return removeProbeEvent(events, "COMMAND_EXECUTION_COMPLETED", "first-command")
			},
			expectErr: "missing execution completion",
		},
		{
			name: "contradictory execution failure",
			mutate: func(events []execution.StructuredEvent) []execution.StructuredEvent {
				events[12] = probeStructuredEvent(13, "COMMAND_EXECUTION_COMPLETED", `{"testId":"first-command","status":"EXECUTION_FAILED"}`)
				return events
			},
			expectErr: "contradicts timeout evidence",
		},
		{
			name: "missing command completion",
			mutate: func(events []execution.StructuredEvent) []execution.StructuredEvent {
				return removeProbeEvent(events, "COMMAND_TEST_COMPLETED", "first-command")
			},
			expectErr: "missing command completion",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := pinnedMultiCommandTimeoutOutput()
			output.StructuredEvents = test.mutate(output.StructuredEvents)
			_, err := validateProbeLifecycle(output, plan)
			if err == nil || !strings.Contains(err.Error(), test.expectErr) {
				t.Fatalf("validateProbeLifecycle() error = %v, want %q", err, test.expectErr)
			}
		})
	}
}

func TestCommandProbeStateRejectsPartialTruncationClassification(t *testing.T) {
	state := newCommandProbeState(consoleCommandTest{ID: "version-command", Assertions: []commandAssertion{{}, {}}})
	for _, event := range []struct {
		kind string
		data string
	}{
		{kind: "COMMAND_REGISTRATION", data: `{"registered":true,"status":"REGISTERED"}`},
		{kind: "COMMAND_EXECUTION_STARTED", data: `{"timeoutSeconds":1}`},
		{kind: "COMMAND_OUTPUT", data: `{"truncated":true,"capturedBytes":4,"observedBytes":8}`},
		{kind: "COMMAND_EXECUTION_COMPLETED", data: `{"status":"COMPLETED","dispatched":true}`},
		{kind: "COMMAND_ASSERTION", data: `{"assertionId":"version-command:1","evaluated":false,"passed":false}`},
	} {
		if err := state.accept(event.kind, json.RawMessage(event.data)); err != nil {
			t.Fatalf("accept(%s) error = %v", event.kind, err)
		}
	}
	if err := state.acceptClassification("command_output_truncated"); err == nil || !strings.Contains(err.Error(), "incomplete assertions") {
		t.Fatalf("partial truncation classification error = %v", err)
	}
}

func TestProbeLifecycleRejectsUnmarkedShortCommandOutput(t *testing.T) {
	plan := testPlan{TargetPlugin: "SuccessFixture", Console: []consoleCommandTest{{ID: "version-command", Assertions: []commandAssertion{{}}}}}
	output := commandProbeOutput(true)
	output.StructuredEvents[9] = probeStructuredEvent(10, "COMMAND_OUTPUT", `{"testId":"version-command","stream":"stdout","lines":["ok"],"capturedBytes":4,"observedBytes":8,"truncated":false}`)
	if _, err := validateProbeLifecycle(output, plan); err == nil || !strings.Contains(err.Error(), "unequal capturedBytes") {
		t.Fatalf("short unmarked output error = %v", err)
	}
}

func TestProbeLifecycleRejectsCommandFailureUnknownClassificationAndMissingCompletion(t *testing.T) {
	plan := testPlan{TargetPlugin: "SuccessFixture", Console: []consoleCommandTest{{ID: "version-command", Assertions: []commandAssertion{{}}}}}

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

func TestCommandProbeStateRejectsSuccessAfterNegativeEvidence(t *testing.T) {
	tests := []struct {
		name           string
		classification string
		events         []struct {
			kind string
			data string
		}
	}{
		{
			name:           "registration failure",
			classification: "command_not_registered",
			events: []struct {
				kind string
				data string
			}{
				{kind: "COMMAND_REGISTRATION", data: `{"registered":false,"status":"NOT_REGISTERED"}`},
			},
		},
		{
			name:           "registration lookup failure",
			classification: "command_registration_failure",
			events: []struct {
				kind string
				data string
			}{
				{kind: "COMMAND_REGISTRATION", data: `{"registered":false,"status":"LOOKUP_FAILED"}`},
			},
		},
		{
			name:           "timeout",
			classification: "command_timeout",
			events: []struct {
				kind string
				data string
			}{
				{kind: "COMMAND_REGISTRATION", data: `{"registered":true,"status":"REGISTERED"}`},
				{kind: "COMMAND_EXECUTION_STARTED", data: `{"timeoutSeconds":1}`},
				{kind: "COMMAND_TIMEOUT", data: `{"timeoutSeconds":1}`},
			},
		},
		{
			name:           "output truncation",
			classification: "command_output_truncated",
			events: []struct {
				kind string
				data string
			}{
				{kind: "COMMAND_REGISTRATION", data: `{"registered":true,"status":"REGISTERED"}`},
				{kind: "COMMAND_EXECUTION_STARTED", data: `{"timeoutSeconds":1}`},
				{kind: "COMMAND_OUTPUT", data: `{"truncated":true,"capturedBytes":4,"observedBytes":8}`},
				{kind: "COMMAND_EXECUTION_COMPLETED", data: `{"status":"COMPLETED","dispatched":true}`},
				{kind: "COMMAND_ASSERTION", data: `{"assertionId":"version-command:1","evaluated":false,"passed":false}`},
			},
		},
		{
			name:           "execution failure",
			classification: "command_execution_failure",
			events: []struct {
				kind string
				data string
			}{
				{kind: "COMMAND_REGISTRATION", data: `{"registered":true,"status":"REGISTERED"}`},
				{kind: "COMMAND_EXECUTION_STARTED", data: `{"timeoutSeconds":1}`},
				{kind: "COMMAND_EXECUTION_COMPLETED", data: `{"status":"EXECUTION_FAILED"}`},
			},
		},
		{
			name:           "assertion failure",
			classification: "command_assertion_failure",
			events: []struct {
				kind string
				data string
			}{
				{kind: "COMMAND_REGISTRATION", data: `{"registered":true,"status":"REGISTERED"}`},
				{kind: "COMMAND_EXECUTION_STARTED", data: `{"timeoutSeconds":1}`},
				{kind: "COMMAND_OUTPUT", data: `{"truncated":false,"capturedBytes":4,"observedBytes":4}`},
				{kind: "COMMAND_EXECUTION_COMPLETED", data: `{"status":"COMPLETED","dispatched":true}`},
				{kind: "COMMAND_ASSERTION", data: `{"assertionId":"version-command:1","evaluated":true,"passed":false}`},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := newCommandProbeState(consoleCommandTest{ID: "version-command", Assertions: []commandAssertion{{}}})
			for _, event := range test.events {
				if err := state.accept(event.kind, json.RawMessage(event.data)); err != nil {
					t.Fatalf("accept(%s) error = %v", event.kind, err)
				}
			}
			if err := state.acceptClassification(test.classification); err != nil {
				t.Fatalf("acceptClassification(%s) error = %v", test.classification, err)
			}
			if err := state.accept("COMMAND_TEST_COMPLETED", json.RawMessage(`{"passed":true}`)); err == nil {
				t.Fatal("negative command evidence was allowed to claim success")
			}
		})
	}
}

func TestCommandProbeStateRejectsSwappedRegistrationClassifications(t *testing.T) {
	for _, test := range []struct {
		status string
		code   string
	}{
		{status: "NOT_REGISTERED", code: "command_registration_failure"},
		{status: "LOOKUP_FAILED", code: "command_not_registered"},
	} {
		t.Run(test.status+"_as_"+test.code, func(t *testing.T) {
			state := newCommandProbeState(consoleCommandTest{ID: "version-command"})
			data := json.RawMessage(fmt.Sprintf(`{"registered":false,"status":%q}`, test.status))
			if err := state.accept("COMMAND_REGISTRATION", data); err != nil {
				t.Fatalf("accept(COMMAND_REGISTRATION) error = %v", err)
			}
			if err := state.acceptClassification(test.code); err == nil || !strings.Contains(err.Error(), "contradicts registration status") {
				t.Fatalf("acceptClassification(%s) error = %v", test.code, err)
			}
		})
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
		probeStructuredEvent(5, "TARGET_REQUIREMENT", `{"role":"TARGET","name":"SuccessFixture","configured":true,"loaded":true,"enabled":true}`),
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
		classification := probeStructuredEvent(13, "CLASSIFICATION", `{"code":"command_assertion_failure","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_EXECUTION","retryable":false,"testId":"version-command"}`)
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

func pinnedMultiCommandTimeoutOutput() execution.CollectedOutput {
	events := []execution.StructuredEvent{
		probeStructuredEvent(1, "TEST_PLAN", `{"status":"LOADED","consoleTests":2,"maximumCommandOutputBytes":4096}`),
		probeStructuredEvent(2, "PROBE_LOADED", `{}`),
		probeStructuredEvent(3, "SERVER_LOADED", `{}`),
		probeStructuredEvent(4, "STABILIZATION_STARTED", `{}`),
		probeStructuredEvent(5, "TARGET_REQUIREMENT", `{"role":"TARGET","name":"SuccessFixture","configured":true,"loaded":true,"enabled":true}`),
		probeStructuredEvent(6, "STABILIZATION_COMPLETED", `{}`),
		probeStructuredEvent(7, "SERVER_READY", `{"requirementsSatisfied":true}`),
		probeStructuredEvent(8, "COMMAND_REGISTRATION", `{"testId":"first-command","registered":true,"status":"REGISTERED"}`),
		probeStructuredEvent(9, "COMMAND_EXECUTION_STARTED", `{"testId":"first-command","timeoutSeconds":10}`),
		probeStructuredEvent(10, "COMMAND_TIMEOUT", `{"testId":"first-command","timeoutSeconds":10}`),
		probeStructuredEvent(11, "CLASSIFICATION", `{"code":"command_timeout","category":"FAILURE_CATEGORY_PLUGIN","stage":"FAILURE_STAGE_EXECUTION","retryable":false,"testId":"first-command"}`),
		probeStructuredEvent(12, "COMMAND_OUTPUT", `{"testId":"first-command","stream":"stdout","lines":["timeout"],"capturedBytes":7,"observedBytes":7,"truncated":false}`),
		probeStructuredEvent(13, "COMMAND_EXECUTION_COMPLETED", `{"testId":"first-command","status":"TIMED_OUT"}`),
		probeStructuredEvent(14, "COMMAND_TEST_COMPLETED", `{"testId":"first-command","passed":false}`),
		probeStructuredEvent(15, "TEST_PLAN", `{"status":"COMPLETED","consoleTests":2,"passed":false,"timedOut":true}`),
		probeStructuredEvent(16, "CLEAN_SHUTDOWN_REQUESTED", `{}`),
		probeStructuredEvent(17, "SERVER_STOPPED", `{"shutdownRequested":true}`),
	}
	var eventBytes int64
	for _, event := range events {
		eventBytes += int64(len(event.Payload))
	}
	return execution.CollectedOutput{StructuredEvents: events, EvidenceUsage: execution.EvidenceUsage{StructuredEventCount: int64(len(events)), StructuredEventBytes: eventBytes}}
}

func insertProbeEvent(events []execution.StructuredEvent, index int, event execution.StructuredEvent) []execution.StructuredEvent {
	return append(events[:index], append([]execution.StructuredEvent{event}, events[index:]...)...)
}

func removeProbeEvent(events []execution.StructuredEvent, eventType, testID string) []execution.StructuredEvent {
	for index, event := range events {
		envelope, err := decodeProbeEnvelope(event.Payload)
		if err == nil && envelope.Type == eventType {
			var data struct {
				TestID string `json:"testId"`
			}
			if json.Unmarshal(envelope.Data, &data) == nil && data.TestID == testID {
				return append(events[:index], events[index+1:]...)
			}
		}
	}
	return events
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
