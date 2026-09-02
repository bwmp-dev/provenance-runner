package gatewayclient

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/runneridentity"
)

func TestLoadConfigBindsInstalledCredentialToActiveRunnerIdentity(t *testing.T) {
	directory := t.TempDir()
	credential := []byte("prc_v1_" + strings.Repeat("A", 43))
	credentialPath := filepath.Join(directory, "credential")
	identityPath := filepath.Join(directory, "identity.json")
	configPath := filepath.Join(directory, "connect.json")
	if err := os.WriteFile(credentialPath, credential, 0o600); err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte("token"))
	document, err := runneridentity.NewPrepared("00000000-0000-0000-0000-000000000011", testRunnerID, tokenHash, "identity-config-test", 900, strings.NewReader(strings.Repeat("z", 32)))
	if err != nil {
		t.Fatal(err)
	}
	credentialHash := sha256.Sum256(credential)
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	document, err = document.Received(runneridentity.Response{CredentialID: "60000000-0000-0000-0000-000000000011", Credential: string(credential), CredentialSHA256: hex.EncodeToString(credentialHash[:]), IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	document, err = document.Active()
	if err != nil {
		t.Fatal(err)
	}
	identityBytes, err := document.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityPath, identityBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	configJSON := strings.Replace(validConfigJSON("credential"), `"expectedScope":{"kind":"platform"}`, `"identityKeyFile":"identity.json","expectedScope":{"kind":"organization","organizationId":"00000000-0000-0000-0000-000000000011"}`, 1)
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath, "test"); err != nil {
		t.Fatalf("active identity was rejected: %v", err)
	}
	if err := os.WriteFile(credentialPath, []byte("different"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath, "test"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched credential error = %v", err)
	}
}

func TestConnectConfigRejectsDuplicateIdentityPath(t *testing.T) {
	data := strings.Replace(validConfigJSON("credential"), `"credentialFile":"credential"`, `"credentialFile":"credential","identityKeyFile":"one","identityKeyFile":"two"`, 1)
	if _, err := decodeConfig([]byte(data)); err == nil {
		t.Fatal("duplicate identityKeyFile was accepted")
	}
}
