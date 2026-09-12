//go:build !linux

package gatewayclient

import (
	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"time"
)

func sealSecretDelivery(_ *runnerv1.JobSpecification, _ string, message *runnerv1.GatewayMessage, _ time.Time) (*testsecrets.Files, time.Time, error) {
	clearTestSecretDelivery(message)
	return nil, time.Time{}, errSecretDeliveryUnavailable
}
