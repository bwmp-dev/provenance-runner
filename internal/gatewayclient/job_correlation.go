package gatewayclient

import (
	"errors"
	"strings"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

const (
	jobCorrelationTraceparentBytes = 55
	jobCorrelationWorkflowBytes    = 44
	jobCorrelationWorkflowPrefix   = "release/"
	zeroUUID                       = "00000000-0000-0000-0000-000000000000"
)

func validateAdvertisedFeatures(features []runnerv1.ProtocolFeature) error {
	seen := make(map[runnerv1.ProtocolFeature]struct{}, len(features))
	for _, feature := range features {
		switch feature {
		case runnerv1.ProtocolFeature_PROTOCOL_FEATURE_DURABLE_LEASE_ACKNOWLEDGEMENTS,
			runnerv1.ProtocolFeature_PROTOCOL_FEATURE_CREDENTIAL_ROTATION,
			runnerv1.ProtocolFeature_PROTOCOL_FEATURE_JOB_CORRELATION_V1,
			runnerv1.ProtocolFeature_PROTOCOL_FEATURE_RESTART_UPLOAD_RECOVERY:
		default:
			return errors.New("runner capabilities contain an unknown protocol feature")
		}
		if _, duplicate := seen[feature]; duplicate {
			return errors.New("runner capabilities contain a duplicate protocol feature")
		}
		seen[feature] = struct{}{}
	}
	return nil
}

func advertisedFeature(features []runnerv1.ProtocolFeature, wanted runnerv1.ProtocolFeature) bool {
	for _, feature := range features {
		if feature == wanted {
			return true
		}
	}
	return false
}

// validateOfferJobCorrelation treats correlation exclusively as immutable
// observability identity. OrganizationScope has already been validated before
// this function runs and remains the authorization input for the offer.
func validateOfferJobCorrelation(job *runnerv1.JobSpecification, expected ExpectedScope, negotiated bool) *OfferRejection {
	correlation := job.GetJobCorrelation()
	if !negotiated {
		if correlation != nil {
			return rejectUnsupported("unexpected_job_correlation", "job correlation was not negotiated")
		}
		return nil
	}
	if correlation == nil {
		return rejectUnsupported("missing_job_correlation", "negotiated job correlation is required")
	}
	workflowID := correlation.GetWorkflowId()
	workflowCandidateID := ""
	if len(workflowID) == jobCorrelationWorkflowBytes && strings.HasPrefix(workflowID, jobCorrelationWorkflowPrefix) {
		workflowCandidateID = workflowID[len(jobCorrelationWorkflowPrefix):]
	}
	if len(correlation.ProtoReflect().GetUnknown()) != 0 ||
		!validTraceparent(correlation.GetTraceparent()) ||
		!validCanonicalNonzeroUUID(correlation.GetOrganizationId()) ||
		!validCanonicalNonzeroUUID(correlation.GetProjectId()) ||
		!validCanonicalNonzeroUUID(workflowCandidateID) ||
		workflowCandidateID != job.GetAttempt().GetReleaseCandidateId() {
		return rejectUnsupported("invalid_job_correlation", "job correlation is malformed or conflicts with attempt identity")
	}
	if expected.Kind == ScopeOrganization && correlation.GetOrganizationId() != expected.OrganizationID {
		return rejectPolicy("job_correlation_scope_mismatch", "job correlation organization conflicts with runner scope")
	}
	return nil
}

func validTraceparent(value string) bool {
	if len(value) != jobCorrelationTraceparentBytes || value[0:3] != "00-" || value[35] != '-' || value[52] != '-' {
		return false
	}
	if !lowerHex(value[3:35]) || !lowerHex(value[36:52]) || !lowerHex(value[53:55]) {
		return false
	}
	if allZeroHex(value[3:35]) || allZeroHex(value[36:52]) {
		return false
	}
	// Version 00 defines only the sampled low bit. Reserved trace-flags fail
	// closed until a later protocol feature explicitly permits them.
	return value[53:55] == "00" || value[53:55] == "01"
}

func lowerHex(value string) bool {
	for index := range len(value) {
		character := value[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func allZeroHex(value string) bool {
	for index := range len(value) {
		if value[index] != '0' {
			return false
		}
	}
	return true
}

func validCanonicalNonzeroUUID(value string) bool {
	return value != zeroUUID && value == strings.ToLower(value) && validateUUID("job correlation UUID", value) == nil
}
