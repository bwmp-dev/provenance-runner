package gatewayclient

import (
	"errors"

	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func terminalProof(message *runnerv1.RunnerMessage) *runnerv1.ExecutionEvidence {
	if message.GetCompleted() != nil {
		return message.GetCompleted().GetExecutionEvidence()
	}
	return message.GetFailed().GetExecutionEvidence()
}

func (s *clientSession) sendRetained(message *runnerv1.RunnerMessage) error {
	if proof := terminalProof(message); proof != nil {
		version, err := terminalevidence.FrozenVersion(proof)
		if err != nil || (version == "provenance.execution-evidence/v1" && !s.terminalEvidenceV1) || (version == "provenance.execution-evidence/v2" && !s.terminalEvidenceV2) {
			return permanent("queued terminal evidence requires current stream advertisement")
		}
	}
	if err := validateTerminalProof(message, s.client.journal.snapshot(), s.client.config.RunnerID); err != nil {
		return permanent("queued terminal evidence identity is invalid")
	}
	return s.send(message)
}

func validateTerminalProof(message *runnerv1.RunnerMessage, state journalState, runnerID string) error {
	proof := terminalProof(message)
	if proof == nil {
		return nil
	}
	if state.Active == nil {
		return errors.New("terminal evidence requires active identity")
	}
	job := new(runnerv1.JobSpecification)
	if proto.Unmarshal(state.Active.Specification, job) != nil {
		return errors.New("terminal evidence active identity is invalid")
	}
	version, err := terminalevidence.FrozenVersion(proof)
	if err != nil {
		return err
	}
	if (version == "provenance.execution-evidence/v2") != state.Active.TerminalEvidenceV2 {
		return errors.New("terminal evidence version differs from executed job")
	}
	if version == "provenance.execution-evidence/v2" {
		return terminalevidence.ValidateFrozenV2(proof, job, runnerID)
	}
	return terminalevidence.ValidateFrozen(proof, job, runnerID)
}

func terminalMessageBound(message *runnerv1.RunnerMessage) error {
	if terminalProof(message) != nil && proto.Size(message) > MaximumMessageBytes {
		return errors.New("terminal evidence message exceeds supported bounds")
	}
	return nil
}
