package paper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

type probeEnvelope struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
}

var requiredProbeOrder = []string{
	"PROBE_LOADED",
	"SERVER_LOADED",
	"STABILIZATION_STARTED",
	"STABILIZATION_COMPLETED",
	"SERVER_READY",
	"CLEAN_SHUTDOWN_REQUESTED",
	"SERVER_STOPPED",
}

var allowedProbeEventTypes = map[string]struct{}{
	"PROBE_LOADED":                {},
	"SERVER_LOADED":               {},
	"SERVER_READY":                {},
	"SERVER_STOPPED":              {},
	"METADATA_INSPECTION":         {},
	"METADATA_SUGGESTION":         {},
	"PLUGIN_STATE":                {},
	"LIFECYCLE_EXCEPTION":         {},
	"CLASSIFICATION":              {},
	"TARGET_REQUIREMENT":          {},
	"STABILIZATION_STARTED":       {},
	"STABILIZATION_COMPLETED":     {},
	"TEST_PLAN":                   {},
	"COMMAND_REGISTRATION":        {},
	"COMMAND_EXECUTION_STARTED":   {},
	"COMMAND_EXECUTION_COMPLETED": {},
	"COMMAND_TIMEOUT":             {},
	"COMMAND_OUTPUT":              {},
	"COMMAND_ASSERTION":           {},
	"COMMAND_TEST_COMPLETED":      {},
	"CLEAN_SHUTDOWN_REQUESTED":    {},
}

var allowedClassificationCodes = map[string]struct{}{
	"plugin_not_found":             {},
	"invalid_metadata":             {},
	"missing_required_dependency":  {},
	"failed_required_dependency":   {},
	"on_load_failure":              {},
	"on_enable_failure":            {},
	"invalid_test_plan":            {},
	"command_not_registered":       {},
	"command_registration_failure": {},
	"command_execution_failure":    {},
	"command_timeout":              {},
	"command_output_truncated":     {},
	"command_assertion_failure":    {},
}

var commandClassificationCodes = map[string]struct{}{
	"command_not_registered":       {},
	"command_registration_failure": {},
	"command_execution_failure":    {},
	"command_timeout":              {},
	"command_output_truncated":     {},
	"command_assertion_failure":    {},
}

type commandProbeState struct {
	expectedAssertions        map[string]struct{}
	seenAssertions            map[string]struct{}
	registrationSeen          bool
	registered                bool
	started                   bool
	outputSeen                bool
	outputTruncated           bool
	timeoutSeen               bool
	timeoutClassificationSeen bool
	assertionFailure          bool
	executionCompleted        bool
	executionStatus           string
	completionSeen            bool
	failure                   bool
}

func newCommandProbeState(test consoleCommandTest) *commandProbeState {
	expected := make(map[string]struct{}, len(test.Assertions))
	for index := range test.Assertions {
		expected[fmt.Sprintf("%s:%d", test.ID, index+1)] = struct{}{}
	}
	return &commandProbeState{expectedAssertions: expected, seenAssertions: make(map[string]struct{}, len(expected))}
}

func (s *commandProbeState) observed() bool {
	return s.registrationSeen || s.started || s.outputSeen || s.timeoutSeen || s.executionCompleted || s.completionSeen || len(s.seenAssertions) > 0
}

func (s *commandProbeState) accept(eventType string, data json.RawMessage) error {
	switch eventType {
	case "COMMAND_REGISTRATION":
		if s.registrationSeen || s.started || s.completionSeen {
			return errors.New("registration event is out of order or duplicated")
		}
		registered, err := requiredBoolean(data, "registered")
		if err != nil {
			return err
		}
		status, err := requiredString(data, "status")
		if err != nil {
			return err
		}
		if registered && status != "REGISTERED" {
			return fmt.Errorf("registered command has status %q", status)
		}
		if !registered && status != "NOT_REGISTERED" && status != "LOOKUP_FAILED" {
			return fmt.Errorf("unregistered command has status %q", status)
		}
		s.registrationSeen = true
		s.registered = registered
		if !registered {
			s.failure = true
		}
	case "COMMAND_EXECUTION_STARTED":
		if !s.registrationSeen || !s.registered || s.started || s.completionSeen || s.failure {
			return errors.New("execution start is out of order or follows a failed registration")
		}
		if timeout, err := requiredInteger(data, "timeoutSeconds"); err != nil || timeout < 1 {
			if err != nil {
				return err
			}
			return errors.New("probe event field timeoutSeconds must be positive")
		}
		s.started = true
	case "COMMAND_TIMEOUT":
		if !s.started || s.executionCompleted || s.completionSeen || s.timeoutSeen {
			return errors.New("timeout event is out of order or duplicated")
		}
		if timeout, err := requiredInteger(data, "timeoutSeconds"); err != nil || timeout < 1 {
			if err != nil {
				return err
			}
			return errors.New("probe event field timeoutSeconds must be positive")
		}
		s.timeoutSeen = true
		s.failure = true
	case "COMMAND_OUTPUT":
		if !s.started || s.executionCompleted || s.completionSeen {
			return errors.New("output event is out of order or follows execution completion")
		}
		if s.timeoutSeen && !s.timeoutClassificationSeen {
			return errors.New("timed-out output is missing its timeout classification")
		}
		truncated, err := requiredBoolean(data, "truncated")
		if err != nil {
			return err
		}
		captured, err := requiredInteger(data, "capturedBytes")
		if err != nil {
			return err
		}
		observed, err := requiredInteger(data, "observedBytes")
		if err != nil {
			return err
		}
		if captured > observed {
			return errors.New("capturedBytes exceeds observedBytes")
		}
		if !truncated && captured != observed {
			return errors.New("non-truncated output has unequal capturedBytes and observedBytes")
		}
		s.outputSeen = true
		s.outputTruncated = s.outputTruncated || truncated
		if truncated {
			s.failure = true
		}
	case "COMMAND_EXECUTION_COMPLETED":
		if !s.started || s.executionCompleted || s.completionSeen {
			return errors.New("execution completion is out of order or duplicated")
		}
		status, err := requiredString(data, "status")
		if err != nil {
			return err
		}
		switch status {
		case "COMPLETED":
			dispatched, err := requiredBoolean(data, "dispatched")
			if err != nil {
				return err
			}
			if !dispatched {
				return errors.New("completed execution was not dispatched")
			}
			if !s.outputSeen {
				return errors.New("completed execution has no output event")
			}
			if s.failure && (!s.outputTruncated || s.timeoutSeen) {
				return errors.New("completed execution contradicts earlier failure evidence")
			}
		case "TIMED_OUT":
			if !s.timeoutSeen {
				return errors.New("timed-out execution has no timeout event")
			}
			if !s.timeoutClassificationSeen || !s.outputSeen {
				return errors.New("timed-out execution has an incomplete timeout trace")
			}
			s.failure = true
		case "EXECUTION_FAILED", "DISPATCH_REJECTED":
			if s.timeoutSeen {
				return errors.New("execution failure contradicts timeout evidence")
			}
			s.failure = true
		default:
			return fmt.Errorf("unsupported execution status %q", status)
		}
		s.executionCompleted = true
		s.executionStatus = status
	case "COMMAND_ASSERTION":
		if !s.executionCompleted || s.executionStatus != "COMPLETED" || s.completionSeen {
			return errors.New("assertion event is out of order or follows failed execution")
		}
		assertionID, err := requiredString(data, "assertionId")
		if err != nil {
			return err
		}
		if _, expected := s.expectedAssertions[assertionID]; !expected {
			return fmt.Errorf("unknown assertion %q", assertionID)
		}
		if _, duplicate := s.seenAssertions[assertionID]; duplicate {
			return fmt.Errorf("duplicate assertion %q", assertionID)
		}
		evaluated, err := requiredBoolean(data, "evaluated")
		if err != nil {
			return err
		}
		passed, err := requiredBoolean(data, "passed")
		if err != nil {
			return err
		}
		if !evaluated {
			if passed || !s.outputTruncated {
				return errors.New("assertion was not evaluated outside a truncated output path")
			}
			s.seenAssertions[assertionID] = struct{}{}
			return nil
		}
		s.seenAssertions[assertionID] = struct{}{}
		if !passed {
			s.failure = true
			s.assertionFailure = true
		}
	case "COMMAND_TEST_COMPLETED":
		if s.completionSeen || !s.registrationSeen {
			return errors.New("command completion is out of order or duplicated")
		}
		passed, err := requiredBoolean(data, "passed")
		if err != nil {
			return err
		}
		if passed {
			if s.failure || !s.executionCompleted || s.executionStatus != "COMPLETED" || len(s.seenAssertions) != len(s.expectedAssertions) {
				return errors.New("command claimed success after a failed or incomplete execution")
			}
		} else {
			if !s.failure {
				return errors.New("command claimed failure without failure evidence")
			}
		}
		s.completionSeen = true
	default:
		return fmt.Errorf("unsupported command event %q", eventType)
	}
	return nil
}

func (s *commandProbeState) acceptClassification(code string) error {
	if !s.registrationSeen || s.completionSeen {
		return errors.New("classification is out of order")
	}
	switch code {
	case "command_not_registered", "command_registration_failure":
		if s.registered {
			return errors.New("registration classification contradicts registered command")
		}
	case "command_execution_failure":
		if !s.executionCompleted || (s.executionStatus != "EXECUTION_FAILED" && s.executionStatus != "DISPATCH_REJECTED") {
			return errors.New("execution failure classification has no matching execution result")
		}
	case "command_timeout":
		if !s.timeoutSeen {
			return errors.New("timeout classification has no timeout event")
		}
		if s.timeoutClassificationSeen || s.outputSeen || s.executionCompleted {
			return errors.New("timeout classification is out of order or duplicated")
		}
		s.timeoutClassificationSeen = true
	case "command_output_truncated":
		if !s.outputTruncated || !s.executionCompleted || s.executionStatus != "COMPLETED" {
			return errors.New("output truncation classification has no completed truncated execution")
		}
		if len(s.seenAssertions) != len(s.expectedAssertions) {
			return errors.New("output truncation classification has incomplete assertions")
		}
	case "command_assertion_failure":
		if !s.assertionFailure {
			return errors.New("assertion failure classification has no failed assertion")
		}
	}
	s.failure = true
	return nil
}

func isCommandClassification(code string) bool {
	_, ok := commandClassificationCodes[code]
	return ok
}

func validateProbeLifecycle(output execution.CollectedOutput, plan testPlan) ([]execution.StructuredEvent, error) {
	if output.StructuredEventError != "" {
		return nil, fmt.Errorf("probe event channel is malformed: %s", output.StructuredEventError)
	}
	if output.EvidenceUsage.EventsTruncated {
		return nil, errors.New("probe event channel exceeded its event limit")
	}
	if len(output.StructuredEvents) == 0 {
		return nil, errors.New("trusted probe emitted no lifecycle events")
	}

	order := make(map[string]int, len(requiredProbeOrder))
	for index, eventType := range requiredProbeOrder {
		order[eventType] = index
	}
	seenRequired := make(map[string]bool, len(requiredProbeOrder))
	nextRequired := 0
	requirements := make(map[string]bool, 1+len(plan.RequiredDependencies))
	requirements[strings.ToLower(plan.TargetPlugin)] = false
	for _, dependency := range plan.RequiredDependencies {
		requirements[strings.ToLower(dependency)] = false
	}
	commandTests := make(map[string]*commandProbeState, len(plan.Console))
	commandOrder := make([]string, len(plan.Console))
	commandIndexes := make(map[string]int, len(plan.Console))
	for index, test := range plan.Console {
		commandTests[test.ID] = newCommandProbeState(test)
		commandOrder[index] = test.ID
		commandIndexes[test.ID] = index
	}

	events := make([]execution.StructuredEvent, 0, len(output.StructuredEvents))
	var lifecycleFailure error
	planLoaded := false
	planCompleted := false
	serverReadySatisfied := false
	nextCommandIndex := 0
	timedOutCommandIndex := -1
	commandStateForEvent := func(testID string) (*commandProbeState, int, error) {
		state, expected := commandTests[testID]
		if !expected {
			return nil, 0, fmt.Errorf("references unknown command test %q", testID)
		}
		index := commandIndexes[testID]
		if timedOutCommandIndex >= 0 && index > timedOutCommandIndex {
			return nil, 0, errors.New("command event occurred after a timed-out command")
		}
		if index != nextCommandIndex {
			if index > nextCommandIndex {
				return nil, 0, fmt.Errorf("command event skips configured command %q", commandOrder[nextCommandIndex])
			}
			return nil, 0, fmt.Errorf("command event for %q occurred after its completion", testID)
		}
		return state, index, nil
	}
	for _, event := range output.StructuredEvents {
		if event.Kind != probeEventKind {
			return events, fmt.Errorf("unexpected structured event kind %q", event.Kind)
		}
		envelope, err := decodeProbeEnvelope(event.Payload)
		if err != nil {
			return events, err
		}
		if _, allowed := allowedProbeEventTypes[envelope.Type]; !allowed {
			return events, fmt.Errorf("unexpected probe event type %q", envelope.Type)
		}
		if requiredIndex, required := order[envelope.Type]; required {
			if seenRequired[envelope.Type] {
				return events, fmt.Errorf("duplicate required probe event %s", envelope.Type)
			}
			if requiredIndex != nextRequired {
				return events, fmt.Errorf("probe event %s is out of order", envelope.Type)
			}
			seenRequired[envelope.Type] = true
			nextRequired++
		}
		events = append(events, execution.StructuredEvent{
			Sequence: uint64(len(events) + 1),
			Kind:     envelope.Type,
			Payload:  append([]byte(nil), envelope.Data...),
		})

		switch envelope.Type {
		case "TEST_PLAN":
			status, err := requiredString(envelope.Data, "status")
			if err != nil {
				return events, err
			}
			switch status {
			case "LOADED":
				if planLoaded {
					return events, errors.New("duplicate loaded TEST_PLAN event")
				}
				count, err := requiredInteger(envelope.Data, "consoleTests")
				if err != nil || count != int64(len(plan.Console)) {
					return events, errors.New("loaded TEST_PLAN consoleTests does not match the materialized plan")
				}
				planLoaded = true
			case "COMPLETED":
				if !planLoaded || planCompleted || len(plan.Console) == 0 || seenRequired["CLEAN_SHUTDOWN_REQUESTED"] {
					return events, errors.New("completed TEST_PLAN event is unexpected")
				}
				count, err := requiredInteger(envelope.Data, "consoleTests")
				if err != nil || count != int64(len(plan.Console)) {
					return events, errors.New("completed TEST_PLAN consoleTests does not match the materialized plan")
				}
				passed, err := requiredBoolean(envelope.Data, "passed")
				if err != nil {
					return events, err
				}
				timedOut, err := requiredBoolean(envelope.Data, "timedOut")
				if err != nil {
					return events, err
				}
				if passed && timedOut {
					return events, errors.New("completed TEST_PLAN cannot be both passed and timed out")
				}
				commandTimedOut := false
				for _, state := range commandTests {
					commandTimedOut = commandTimedOut || state.timeoutSeen
				}
				if timedOut != commandTimedOut {
					return events, errors.New("completed TEST_PLAN timedOut does not match command timeout evidence")
				}
				planCompleted = true
				if !passed && lifecycleFailure == nil {
					lifecycleFailure = errors.New("probe reported a failed console test plan")
				}
			case "INVALID":
				if lifecycleFailure == nil {
					lifecycleFailure = errors.New("probe rejected the materialized test plan")
				}
			default:
				return events, fmt.Errorf("unexpected TEST_PLAN status %q", status)
			}
		case "COMMAND_REGISTRATION", "COMMAND_EXECUTION_STARTED", "COMMAND_EXECUTION_COMPLETED", "COMMAND_TIMEOUT", "COMMAND_OUTPUT", "COMMAND_ASSERTION", "COMMAND_TEST_COMPLETED":
			if !seenRequired["SERVER_READY"] || seenRequired["CLEAN_SHUTDOWN_REQUESTED"] {
				return events, fmt.Errorf("probe event %s occurred outside the command execution window", envelope.Type)
			}
			testID, err := requiredString(envelope.Data, "testId")
			if err != nil {
				return events, err
			}
			state, commandIndex, err := commandStateForEvent(testID)
			if err != nil {
				return events, fmt.Errorf("probe event %s: %w", envelope.Type, err)
			}
			if err := state.accept(envelope.Type, envelope.Data); err != nil {
				return events, fmt.Errorf("command test %q: %w", testID, err)
			}
			if state.timeoutSeen {
				timedOutCommandIndex = commandIndex
			}
			if state.completionSeen {
				nextCommandIndex++
			}
		case "TARGET_REQUIREMENT":
			name, satisfied, err := decodeRequirement(envelope.Data)
			if err != nil {
				return events, err
			}
			key := strings.ToLower(name)
			if _, expected := requirements[key]; expected {
				if requirements[key] {
					return events, fmt.Errorf("duplicate requirement result for %q", name)
				}
				requirements[key] = satisfied
			}
			if !satisfied && lifecycleFailure == nil {
				lifecycleFailure = fmt.Errorf("plugin requirement %q was not loaded and enabled", name)
			}
		case "CLASSIFICATION":
			code, err := classificationCode(envelope.Data)
			if err != nil {
				return events, err
			}
			if isCommandClassification(code) {
				testID, err := requiredString(envelope.Data, "testId")
				if err != nil {
					return events, fmt.Errorf("command classification %s: %w", code, err)
				}
				state, commandIndex, err := commandStateForEvent(testID)
				if err != nil {
					return events, fmt.Errorf("command classification %s: %w", code, err)
				}
				if err := state.acceptClassification(code); err != nil {
					return events, fmt.Errorf("command test %q: %w", testID, err)
				}
				if state.timeoutSeen {
					timedOutCommandIndex = commandIndex
				}
			}
			if lifecycleFailure == nil {
				lifecycleFailure = fmt.Errorf("probe classified the workload as %s", code)
			}
		case "LIFECYCLE_EXCEPTION":
			if lifecycleFailure == nil {
				lifecycleFailure = errors.New("probe observed a plugin lifecycle exception")
			}
		case "SERVER_READY":
			if ok, err := requiredBoolean(envelope.Data, "requirementsSatisfied"); err != nil {
				return events, err
			} else {
				serverReadySatisfied = ok
				if !ok && lifecycleFailure == nil {
					lifecycleFailure = errors.New("probe reported unsatisfied server-ready requirements")
				}
			}
		case "SERVER_STOPPED":
			if ok, err := requiredBoolean(envelope.Data, "shutdownRequested"); err != nil {
				return events, err
			} else if !ok && lifecycleFailure == nil {
				lifecycleFailure = errors.New("server stopped without the probe-requested clean shutdown")
			}
		}
	}
	if nextRequired != len(requiredProbeOrder) {
		return events, fmt.Errorf("missing required probe event %s", requiredProbeOrder[nextRequired])
	}
	if !planLoaded {
		return events, errors.New("missing loaded TEST_PLAN event")
	}
	if len(plan.Console) > 0 && serverReadySatisfied {
		if !planCompleted {
			return events, errors.New("missing completed TEST_PLAN event")
		}
		for index, testID := range commandOrder {
			state := commandTests[testID]
			if timedOutCommandIndex >= 0 && index > timedOutCommandIndex {
				if state.observed() {
					return events, fmt.Errorf("command test %q emitted events after a timed-out command", testID)
				}
				continue
			}
			if !state.completionSeen {
				return events, fmt.Errorf("missing command completion for %q", testID)
			}
			if state.started && !state.executionCompleted {
				return events, fmt.Errorf("missing execution completion for %q", testID)
			}
			if state.failure && lifecycleFailure == nil {
				lifecycleFailure = fmt.Errorf("command test %q failed", testID)
			}
		}
	}
	for name, satisfied := range requirements {
		if !satisfied && lifecycleFailure == nil {
			lifecycleFailure = fmt.Errorf("missing successful requirement result for %q", name)
		}
	}
	return events, lifecycleFailure
}

func decodeProbeEnvelope(payload json.RawMessage) (probeEnvelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var envelope probeEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return probeEnvelope{}, fmt.Errorf("decode probe event: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return probeEnvelope{}, errors.New("decode probe event: trailing JSON value")
	}
	if envelope.Type == "" || !json.Valid(envelope.Data) {
		return probeEnvelope{}, errors.New("decode probe event: type and object data are required")
	}
	if _, err := time.Parse(time.RFC3339Nano, envelope.Timestamp); err != nil {
		return probeEnvelope{}, errors.New("decode probe event: timestamp must be RFC 3339")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Data, &object); err != nil || object == nil {
		return probeEnvelope{}, errors.New("decode probe event: data must be a JSON object")
	}
	return envelope, nil
}

func decodeRequirement(data json.RawMessage) (string, bool, error) {
	var requirement struct {
		Name       string `json:"name"`
		Configured *bool  `json:"configured"`
		Loaded     *bool  `json:"loaded"`
		Enabled    *bool  `json:"enabled"`
	}
	if err := json.Unmarshal(data, &requirement); err != nil || requirement.Name == "" || requirement.Configured == nil || requirement.Loaded == nil || requirement.Enabled == nil {
		return "", false, errors.New("TARGET_REQUIREMENT is missing authoritative status fields")
	}
	return requirement.Name, *requirement.Configured && *requirement.Loaded && *requirement.Enabled, nil
}

func classificationCode(data json.RawMessage) (string, error) {
	var classification struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &classification); err != nil {
		return "", errors.New("CLASSIFICATION contains an invalid code")
	}
	if _, allowed := allowedClassificationCodes[classification.Code]; !allowed {
		return "", errors.New("CLASSIFICATION contains an unsupported code")
	}
	return classification.Code, nil
}

func requiredString(data json.RawMessage, field string) (string, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return "", fmt.Errorf("%s event data is invalid", field)
	}
	encoded, exists := values[field]
	if !exists {
		return "", fmt.Errorf("probe event is missing %s", field)
	}
	var value string
	if err := json.Unmarshal(encoded, &value); err != nil || value == "" {
		return "", fmt.Errorf("probe event field %s must be a non-empty string", field)
	}
	return value, nil
}

func requiredInteger(data json.RawMessage, field string) (int64, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return 0, fmt.Errorf("%s event data is invalid", field)
	}
	encoded, exists := values[field]
	if !exists {
		return 0, fmt.Errorf("probe event is missing %s", field)
	}
	var value int64
	if err := json.Unmarshal(encoded, &value); err != nil || value < 0 {
		return 0, fmt.Errorf("probe event field %s must be a non-negative integer", field)
	}
	return value, nil
}

func requiredBoolean(data json.RawMessage, field string) (bool, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return false, fmt.Errorf("%s event data is invalid", field)
	}
	encoded, exists := values[field]
	if !exists {
		return false, fmt.Errorf("probe event is missing %s", field)
	}
	var value bool
	if err := json.Unmarshal(encoded, &value); err != nil {
		return false, fmt.Errorf("probe event field %s must be boolean", field)
	}
	return value, nil
}
