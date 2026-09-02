package runneridentity

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

const (
	vectorOrganizationID = "00000000-0000-0000-0000-000000000011"
	vectorRunnerID       = "50000000-0000-0000-0000-000000000011"
	vectorTokenHash      = "227d5c86d147a519fa4caf435bb5cc85acbc20f709b94af9371122eaa6e6bbf9"
	vectorPublicKey      = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	vectorSignature      = "gfTLqWihY048vNn-hZvs81xk7pmEdsM2WmCPGimPDrOoU8Gl1YW5BFg5lsh4ZYZiAGlv3XUzoH5oholxRcVDAQ"
)

func TestReleasedRegistrationProofVector(t *testing.T) {
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	document := Document{
		SchemaVersion: SchemaVersion, Phase: PhasePrepared,
		OrganizationID: vectorOrganizationID, RunnerID: vectorRunnerID,
		PrivateKeySeed: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A", PublicKey: vectorPublicKey,
		PublicKeyFingerprint: "sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9",
		TokenSHA256:          vectorTokenHash, IdempotencyKey: "enrollment-test-00000001", CredentialTTLSeconds: 900,
	}
	message := []byte("provenance.runner.registration.v1\norganization_id:" + vectorOrganizationID + "\nrunner_id:" + vectorRunnerID + "\nregistration_token_sha256:" + vectorTokenHash + "\npublic_key_base64url:" + vectorPublicKey + "\n")
	signature, err := document.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if got := rawURL(signature); got != vectorSignature {
		t.Fatalf("released signature = %q", got)
	}
	clear(seed)
}

func TestIdentityLifecycleNeverPersistsActiveCredentialOrTerminalKey(t *testing.T) {
	tokenHash := sha256.Sum256([]byte("registration token"))
	document, err := NewPrepared(vectorOrganizationID, vectorRunnerID, tokenHash, "enrollment-attempt-0001", 900, strings.NewReader(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	credential := "prc_v1_" + strings.Repeat("A", 43)
	now := time.Date(2026, 9, 2, 1, 2, 3, 0, time.UTC)
	digest := sha256.Sum256([]byte(credential))
	received, err := document.Received(Response{CredentialID: "60000000-0000-4000-8000-000000000011", Credential: credential, CredentialSHA256: hex.EncodeToString(digest[:]), IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	active, err := received.Active()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := active.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), credential) || active.PrivateKeySeed == "" || active.Response.CredentialSHA256 == "" {
		t.Fatalf("active identity leaked credential or lost identity: %s", encoded)
	}
	terminal, err := document.Terminated("credential_not_replayable")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = terminal.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if terminal.PrivateKeySeed != "" || strings.Contains(string(encoded), document.PrivateKeySeed) {
		t.Fatalf("terminal identity retained private key: %s", encoded)
	}
}

func TestIdentityDecodeRejectsDuplicateUnknownAndTrailingState(t *testing.T) {
	for name, data := range map[string]string{
		"duplicate": `{"schemaVersion":"provenance.runner-identity/v1alpha1","schemaVersion":"provenance.runner-identity/v1alpha1"}`,
		"unknown":   `{"unknown":true}`,
		"trailing":  `{}` + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(data)); err == nil {
				t.Fatal("hostile identity document was accepted")
			}
		})
	}
}

func rawURL(value []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var result strings.Builder
	for index := 0; index < len(value); index += 3 {
		chunk := uint32(value[index]) << 16
		remaining := len(value) - index
		if remaining > 1 {
			chunk |= uint32(value[index+1]) << 8
		}
		if remaining > 2 {
			chunk |= uint32(value[index+2])
		}
		result.WriteByte(alphabet[(chunk>>18)&63])
		result.WriteByte(alphabet[(chunk>>12)&63])
		if remaining > 1 {
			result.WriteByte(alphabet[(chunk>>6)&63])
		}
		if remaining > 2 {
			result.WriteByte(alphabet[chunk&63])
		}
	}
	return result.String()
}
