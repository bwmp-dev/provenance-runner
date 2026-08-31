package paper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

var safeFailureCode = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

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
	"PROBE_LOADED":             {},
	"SERVER_LOADED":            {},
	"SERVER_READY":             {},
	"SERVER_STOPPED":           {},
	"METADATA_INSPECTION":      {},
	"METADATA_SUGGESTION":      {},
	"PLUGIN_STATE":             {},
	"LIFECYCLE_EXCEPTION":      {},
	"CLASSIFICATION":           {},
	"TARGET_REQUIREMENT":       {},
	"STABILIZATION_STARTED":    {},
	"STABILIZATION_COMPLETED":  {},
	"CLEAN_SHUTDOWN_REQUESTED": {},
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

	events := make([]execution.StructuredEvent, 0, len(output.StructuredEvents))
	var lifecycleFailure error
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
			} else if !ok && lifecycleFailure == nil {
				lifecycleFailure = errors.New("probe reported unsatisfied server-ready requirements")
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
	if err := json.Unmarshal(data, &classification); err != nil || !safeFailureCode.MatchString(classification.Code) {
		return "", errors.New("CLASSIFICATION contains an invalid code")
	}
	return classification.Code, nil
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
