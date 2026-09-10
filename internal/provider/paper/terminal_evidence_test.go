package paper

import (
	"encoding/json"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
)

func TestTerminalProjectionUsesValidatedClosedLifecycle(t *testing.T) {
	plan := testPlan{TargetPlugin: "SuccessFixture", RequiredDependencies: []string{"DependencyFixture"}}
	var observations []terminalevidence.Observation
	if _, err := validateProbeLifecycle(happyProbeOutput(), plan, &observations); err != nil {
		t.Fatal(err)
	}
	if len(observations) != 4 {
		t.Fatalf("observed %d assertions", len(observations))
	}
	if observations[0].Type != "plugin-enabled" || !observations[0].Enabled || observations[1].Type != "dependency-present" || observations[2].Type != "startup-ready" || !observations[2].RequirementsSatisfied || observations[3].Type != "clean-shutdown" || !observations[3].ReportedShutdownRequested {
		t.Fatal("lost validated lifecycle facts")
	}
	output := happyProbeOutput()
	replaceProbeEvent(t, &output, "TARGET_REQUIREMENT", `{"role":"TARGET","name":"SuccessFixture","configured":true,"loaded":true,"enabled":false}`)
	replaceProbeEvent(t, &output, "SERVER_READY", `{"requirementsSatisfied":false}`)
	if _, err := validateProbeLifecycle(output, plan, &observations); err == nil {
		t.Fatal("invalid lifecycle accepted")
	}
	if len(observations) != 4 || observations[0].Enabled || observations[2].RequirementsSatisfied {
		t.Fatal("known failure lost or promoted")
	}
	// A malformed event never becomes a closed observation; preceding known facts
	// may remain partial but the malformed and missing successors do not.
	output = happyProbeOutput()
	output.StructuredEvents[4].Payload = json.RawMessage(`{"timestamp":"2026-08-30T00:00:00Z","type":"TARGET_REQUIREMENT","data":{"role":"TARGET","name":"SuccessFixture","configured":true,"loaded":true,"enabled":"secret-marker"}}`)
	if _, err := validateProbeLifecycle(output, plan, &observations); err == nil {
		t.Fatal("malformed requirement accepted")
	}
	if len(observations) != 0 {
		t.Fatal("malformed requirement produced evidence")
	}
}

func TestConsoleProjectionRequiresExplicitRegex(t *testing.T) {
	for _, operator := range []string{"regex", "contains", ""} {
		plan := testPlan{TargetPlugin: "SuccessFixture", Console: []consoleCommandTest{{ID: "version-command", Assertions: []commandAssertion{{Operator: operator}}}}}
		var observations []terminalevidence.Observation
		if _, err := validateProbeLifecycle(commandProbeOutput(true), plan, &observations); err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, o := range observations {
			if o.Type == "console-regex" {
				count++
				if !o.Registered || !o.ExecutionCompleted || !o.Evaluated || !o.Passed || o.OutputTruncated {
					t.Fatal("console facts changed")
				}
			}
		}
		if (count == 1) != (operator == "regex") {
			t.Fatal("unsupported/default console operator projected")
		}
	}
}

func TestV2ConsoleProjectionUsesExplicitValidatedOperator(t *testing.T) {
	for _, operator := range []string{"regex", "contains", ""} {
		for _, passed := range []bool{true, false} {
			plan := testPlan{TargetPlugin: "SuccessFixture", Console: []consoleCommandTest{{ID: "version-command", Assertions: []commandAssertion{{Operator: operator}}}}}
			var observations []terminalevidence.Observation
			_, err := validateProbeLifecycleVersion(commandProbeOutput(passed), plan, true, &observations)
			if (err == nil) != passed {
				t.Fatal("lifecycle failure classification changed", err)
			}
			count := 0
			for _, o := range observations {
				if o.Type != "console-regex" && o.Type != "console-contains" {
					continue
				}
				count++
				kind := "console-regex"
				if operator == "contains" {
					kind = "console-contains"
				}
				if o.Type != kind || o.TestID != "version-command" || o.AssertionID != "version-command:1" || !o.Registered || !o.ExecutionCompleted || !o.Evaluated || o.Passed != passed || o.OutputTruncated {
					t.Fatal("validated operator/facts changed")
				}
			}
			if (count == 1) != (operator != "") {
				t.Fatal("implicit/default operator produced evidence")
			}
		}
	}
}
