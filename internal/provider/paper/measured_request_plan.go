package paper

import (
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

// MeasuredRequestPlan is closed provider metadata for root admission. It grants
// no authority and owns no descriptors. The service must match descriptor count,
// copy/hash every role through its controller and obtain fresh reconciliation.
type MeasuredRequestPlan struct {
	job           *p.JobSpecification
	inputs        *MeasuredInputPlan
	configuration []byte
}

func (m *MeasuredRequestPlan) Job() *p.JobSpecification {
	if m == nil || m.job == nil {
		return nil
	}
	return proto.Clone(m.job).(*p.JobSpecification)
}
func (m *MeasuredRequestPlan) Inputs() []MeasuredInputIdentity {
	if m == nil {
		return nil
	}
	return m.inputs.Inputs()
}
func (m *MeasuredRequestPlan) GuestConfiguration() []byte {
	if m == nil {
		return nil
	}
	return append([]byte(nil), m.configuration...)
}

// PrepareMeasuredRequest verifies the runtime using the root's provisioned
// source/key, without downloading anything. Until the measured secret-injection
// path is composed, secret-bearing jobs fail closed rather than lose their
// declared inputs or fall back to the legacy execution path.
func (s *RuntimeSource) PrepareMeasuredRequest(raw []byte, maximum uint64) (*MeasuredRequestPlan, error) {
	job, manifest, err := DecodeMeasuredRequest(raw)
	if err != nil || len(job.TestSecrets) != 0 {
		return nil, ErrMeasuredInputPlan
	}
	plan, err := s.DeriveMeasuredInputPlan(job, manifest, maximum)
	if err != nil {
		return nil, ErrMeasuredInputPlan
	}
	configuration, err := plan.GuestConfiguration(job)
	if err != nil {
		return nil, ErrMeasuredInputPlan
	}
	return &MeasuredRequestPlan{job, plan, configuration}, nil
}
