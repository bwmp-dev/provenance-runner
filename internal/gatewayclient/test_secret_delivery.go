package gatewayclient

import runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"

// Until authenticated worker delivery is implemented, every delivery is
// unsolicited. Never marshal or hash it through the ordinary replay machinery.
// Clear only buffers we own; this is not a promise to erase transport copies.
func refuseTestSecretDelivery(message *runnerv1.GatewayMessage) error {
	if _, delivery := message.GetPayload().(*runnerv1.GatewayMessage_TestSecretsDelivery); !delivery {
		return nil
	}
	clearTestSecretDelivery(message)
	return permanent("unsolicited test-secret delivery")
}

func clearTestSecretDelivery(message *runnerv1.GatewayMessage) {
	for _, secret := range message.GetTestSecretsDelivery().GetSecrets() {
		if secret != nil {
			clear(secret.Value)
			secret.Value = nil
		}
	}
}
