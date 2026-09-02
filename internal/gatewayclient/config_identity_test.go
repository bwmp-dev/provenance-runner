package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/runneridentity"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

func activeIdentityConfig(t *testing.T, initialCredential []byte) (string, string, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(directory, "credential")
	identityPath := filepath.Join(directory, "identity.json")
	configPath := filepath.Join(directory, "connect.json")
	if err := os.WriteFile(credentialPath, initialCredential, 0o600); err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte("token"))
	document, err := runneridentity.NewPrepared("00000000-0000-0000-0000-000000000011", testRunnerID, tokenHash, "identity-config-test", 900, strings.NewReader(strings.Repeat("z", 32)))
	if err != nil {
		t.Fatal(err)
	}
	credentialHash := sha256.Sum256(initialCredential)
	now := time.Now().UTC()
	document, err = document.Received(runneridentity.Response{CredentialID: "60000000-0000-0000-0000-000000000011", Credential: string(initialCredential), CredentialSHA256: hex.EncodeToString(credentialHash[:]), IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute)})
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
	return configPath, credentialPath, filepath.Join(directory, ".provenance-runner-journal.json")
}

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

func TestLoadConfigAcceptsOnlyDurablyCommittedRunnerBoundRotation(t *testing.T) {
	initial := canonicalCredential(70)
	rotated := canonicalCredential(71)
	configPath, _, journalPath := activeIdentityConfig(t, initial)
	config, err := LoadConfig(configPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClientWithWorker(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	client.now = func() time.Time { return now }
	session := &clientSession{client: client, rootContext: context.Background(), send: func(*runnerv1.RunnerMessage) error { return nil }}
	if err := session.handleCredentialRotation(rotationPayload(now, "60000000-0000-4000-8000-000000000071", rotated), now); !errors.Is(err, errCredentialRotationReconnect) {
		t.Fatalf("apply rotation = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if restarted, err := LoadConfig(configPath, "test"); err != nil || !bytes.Equal(restarted.credential, rotated) {
		t.Fatalf("committed rotation restart credential=%q err=%v", restarted.credential, err)
	}
	reopened, err := newClientWithWorker(mustLoadConfig(t, configPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.reconcileCredentialRotationAfterAuthentication(); err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
	journal, err := openJournal(journalPath)
	if err != nil || journal.snapshot().CredentialRotation != nil || journal.snapshot().CommittedCredential == nil {
		t.Fatalf("reconciled journal = %#v, %v", journal.snapshot(), err)
	}
	if _, err := LoadConfig(configPath, "test"); err != nil {
		t.Fatalf("restart after acknowledgement lost committed binding: %v", err)
	}
}

func TestLoadConfigRejectsPendingConflictingStaleAndWrongRunnerRotationBindings(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	initial := canonicalCredential(72)
	rotated := canonicalCredential(73)
	fingerprint := sha256.Sum256(rotated)
	otherFingerprint := sha256.Sum256(canonicalCredential(74))
	rotationID := "60000000-0000-4000-8000-000000000073"
	otherRunner := "50000000-0000-0000-0000-000000000099"
	for _, test := range []struct {
		name   string
		mutate func(*journalState)
	}{
		{name: "pending", mutate: func(state *journalState) {
			state.CredentialRotation = &journalCredentialRotation{RotationID: rotationID, Fingerprint: bytes.Clone(fingerprint[:]), IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute), ReconnectBefore: now.Add(2 * time.Minute)}
		}},
		{name: "conflicting pending", mutate: func(state *journalState) {
			state.CommittedCredential = &journalCommittedCredential{RunnerID: testRunnerID, RotationID: rotationID, Fingerprint: bytes.Clone(fingerprint[:]), IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute), PersistedAt: now}
			state.CredentialRotation = &journalCredentialRotation{RotationID: "60000000-0000-4000-8000-000000000074", Fingerprint: bytes.Clone(otherFingerprint[:]), IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute), ReconnectBefore: now.Add(2 * time.Minute)}
		}},
		{name: "wrong runner", mutate: func(state *journalState) {
			state.CommittedCredential = &journalCommittedCredential{RunnerID: otherRunner, RotationID: rotationID, Fingerprint: bytes.Clone(fingerprint[:]), IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute), PersistedAt: now}
		}},
		{name: "wrong fingerprint", mutate: func(state *journalState) {
			state.CommittedCredential = &journalCommittedCredential{RunnerID: testRunnerID, RotationID: rotationID, Fingerprint: bytes.Clone(otherFingerprint[:]), IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute), PersistedAt: now}
		}},
		{name: "stale", mutate: func(state *journalState) {
			state.CommittedCredential = &journalCommittedCredential{RunnerID: testRunnerID, RotationID: rotationID, Fingerprint: bytes.Clone(fingerprint[:]), IssuedAt: now.Add(-16 * time.Minute), ExpiresAt: now.Add(-time.Minute), PersistedAt: now.Add(-2 * time.Minute)}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			configPath, credentialPath, journalPath := activeIdentityConfig(t, initial)
			if err := os.WriteFile(credentialPath, rotated, 0o600); err != nil {
				t.Fatal(err)
			}
			journal, err := openJournal(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.update(func(state *journalState) error { test.mutate(state); return nil }); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(configPath, "test"); err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Fatalf("unsafe rotation binding error = %v", err)
			}
		})
	}
}

func mustLoadConfig(t *testing.T, path string) Config {
	t.Helper()
	config, err := LoadConfig(path, "test")
	if err != nil {
		t.Fatal(err)
	}
	return config
}
