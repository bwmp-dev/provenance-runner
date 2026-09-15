package execution

import (
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

// FreezeTerminalEvidence consumes only provider observations and the original
// executed context. Opaque network observations are never replaced with public
// snapshot fields, including on validation failure.
func (r Result) FreezeTerminalEvidence(runnerID string) (*p.ExecutionEvidence, error) {
	if r.MeasuredNetwork != nil {
		if r.TerminalContext == nil || r.MeasuredRuntime != nil {
			return nil, terminalevidence.ErrInvalid
		}
		return terminalevidence.BuildObservedNetwork(r.TerminalContext, runnerID, r.TerminalObservations, r.MeasuredNetwork)
	}
	if r.TerminalContext == nil {
		return nil, nil
	}
	return terminalevidence.Build(r.TerminalContext, runnerID, r.TerminalObservations, r.MeasuredRuntime)
}
