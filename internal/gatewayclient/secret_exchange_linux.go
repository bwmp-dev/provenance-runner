//go:build linux

package gatewayclient

import (
	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"time"
)

func sealSecretDelivery(job *runnerv1.JobSpecification, requestID string, message *runnerv1.GatewayMessage, now time.Time) (*testsecrets.Files, time.Time, error) {
	inputs, expiry, err := testsecrets.TakeDelivery(job, requestID, message, now)
	defer testsecrets.ClearInputs(inputs)
	if err != nil {
		return nil, time.Time{}, errSecretDeliveryUnavailable
	}
	files, err := testsecrets.New(inputs)
	if err != nil {
		return nil, time.Time{}, errSecretDeliveryUnavailable
	}
	return files, expiry, nil
}
