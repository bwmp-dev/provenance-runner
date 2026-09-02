//go:build linux

package gatewayclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

func TestLoadConfigRecoversCrashAfterCredentialDurabilityBeforeRotationCommit(t *testing.T) {
	initial := canonicalCredential(80)
	rotated := canonicalCredential(81)
	configPath, credentialPath, journalPath := activeIdentityConfig(t, initial)
	config := mustLoadConfig(t, configPath)
	client, err := newClientWithWorker(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	store, ok := client.config.credentialStore.(*linuxCredentialStore)
	if !ok {
		t.Fatal("rotation-capable credential store was not constructed")
	}
	store.hooks.afterDirSync = func() error { return errors.New("injected crash after credential durability") }
	now := time.Now().UTC().Truncate(time.Millisecond)
	client.now = func() time.Time { return now }
	session := &clientSession{client: client, rootContext: context.Background(), send: func(*runnerv1.RunnerMessage) error {
		t.Fatal("rotation acknowledgement was sent after injected pre-commit crash")
		return nil
	}}
	if err := session.handleCredentialRotation(rotationPayload(now, "60000000-0000-4000-8000-000000000081", rotated), now); err == nil {
		t.Fatal("injected credential-store failure was ignored")
	}
	installed, err := os.ReadFile(credentialPath)
	if err != nil || !bytes.Equal(installed, rotated) {
		t.Fatalf("durable post-crash credential = %q, %v", installed, err)
	}
	state := client.journal.snapshot()
	if state.CredentialRotation == nil || state.CredentialRotation.RunnerID != testRunnerID || !state.CredentialRotation.PersistedAt.IsZero() || state.CommittedCredential != nil {
		t.Fatalf("pre-commit crash journal = %#v", state)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	restartedConfig, err := LoadConfig(configPath, "test")
	if err != nil || !bytes.Equal(restartedConfig.credential, rotated) {
		t.Fatalf("pending rotation restart credential=%q err=%v", restartedConfig.credential, err)
	}
	restarted, err := newClientWithWorker(restartedConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return now.Add(time.Second) }
	if err := restarted.reconcileCredentialRotationAfterAuthentication(); err != nil {
		t.Fatalf("authenticated pending reconciliation = %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	reconciled, err := openJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	state = reconciled.snapshot()
	if state.CredentialRotation != nil || state.CommittedCredential == nil || state.CommittedCredential.RunnerID != testRunnerID || !bytes.Equal(state.CommittedCredential.Fingerprint, sha256Digest(rotated)) {
		t.Fatalf("reconciled crash journal = %#v", state)
	}
	if _, err := LoadConfig(configPath, "test"); err != nil {
		t.Fatalf("post-reconciliation restart lost committed binding: %v", err)
	}
}

func TestLoadConfigRecoversSecondRotationCrashAfterCredentialDurabilityBeforeCommit(t *testing.T) {
	initial := canonicalCredential(82)
	first := canonicalCredential(83)
	second := canonicalCredential(84)
	configPath, credentialPath, journalPath := activeIdentityConfig(t, initial)
	client, err := newClientWithWorker(mustLoadConfig(t, configPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	completeIdentityRotation(t, client, now, "60000000-0000-4000-8000-000000000083", first)
	state := client.journal.snapshot()
	if state.CredentialRotation != nil || state.CommittedCredential == nil || state.CommittedCredential.RotationID != "60000000-0000-4000-8000-000000000083" || !bytes.Equal(state.CommittedCredential.Fingerprint, sha256Digest(first)) {
		t.Fatalf("first reconciled rotation journal = %#v", state)
	}

	store, ok := client.config.credentialStore.(*linuxCredentialStore)
	if !ok {
		t.Fatal("rotation-capable credential store was not constructed")
	}
	store.hooks.afterDirSync = func() error { return errors.New("injected crash after second credential durability") }
	secondAt := now.Add(time.Second)
	client.now = func() time.Time { return secondAt }
	session := &clientSession{client: client, rootContext: context.Background(), send: func(*runnerv1.RunnerMessage) error {
		t.Fatal("second rotation acknowledgement was sent after injected pre-commit crash")
		return nil
	}}
	if err := session.handleCredentialRotation(rotationPayload(secondAt, "60000000-0000-4000-8000-000000000084", second), secondAt); err == nil {
		t.Fatal("injected second credential-store failure was ignored")
	}
	installed, err := os.ReadFile(credentialPath)
	if err != nil || !bytes.Equal(installed, second) {
		t.Fatalf("durable second post-crash credential = %q, %v", installed, err)
	}
	state = client.journal.snapshot()
	if state.CredentialRotation == nil || state.CredentialRotation.RunnerID != testRunnerID || !state.CredentialRotation.PersistedAt.IsZero() ||
		state.CommittedCredential == nil || state.CommittedCredential.RotationID != "60000000-0000-4000-8000-000000000083" {
		t.Fatalf("second pre-commit crash journal = %#v", state)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	assertPendingRotationRestartReconciles(t, configPath, journalPath, secondAt.Add(time.Second), "60000000-0000-4000-8000-000000000084", second)
}

func TestLoadConfigReconcilesSecondRotationJournalCommitFailure(t *testing.T) {
	initial := canonicalCredential(85)
	first := canonicalCredential(86)
	second := canonicalCredential(87)
	configPath, credentialPath, journalPath := activeIdentityConfig(t, initial)
	client, err := newClientWithWorker(mustLoadConfig(t, configPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	completeIdentityRotation(t, client, now, "60000000-0000-4000-8000-000000000086", first)
	store, ok := client.config.credentialStore.(*linuxCredentialStore)
	if !ok {
		t.Fatal("rotation-capable credential store was not constructed")
	}
	originalJournalPath := client.journal.path
	store.hooks.afterDirSync = func() error {
		client.journal.path = filepath.Join(filepath.Dir(journalPath), "missing", "journal.json")
		return nil
	}
	secondAt := now.Add(time.Second)
	client.now = func() time.Time { return secondAt }
	session := &clientSession{client: client, rootContext: context.Background(), send: func(*runnerv1.RunnerMessage) error {
		t.Fatal("second rotation acknowledgement was sent after injected journal commit failure")
		return nil
	}}
	if err := session.handleCredentialRotation(rotationPayload(secondAt, "60000000-0000-4000-8000-000000000087", second), secondAt); !errors.Is(err, errCredentialRotationReconnect) {
		t.Fatalf("second rotation journal commit failure = %v", err)
	}
	client.journal.path = originalJournalPath
	store.hooks.afterDirSync = nil
	installed, err := os.ReadFile(credentialPath)
	if err != nil || !bytes.Equal(installed, second) {
		t.Fatalf("durable second credential after journal failure = %q, %v", installed, err)
	}
	state := client.journal.snapshot()
	if state.CredentialRotation == nil || !state.CredentialRotation.PersistedAt.IsZero() || state.CommittedCredential == nil ||
		state.CommittedCredential.RotationID != "60000000-0000-4000-8000-000000000086" {
		t.Fatalf("second journal commit failure state = %#v", state)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	assertPendingRotationRestartReconciles(t, configPath, journalPath, secondAt.Add(time.Second), "60000000-0000-4000-8000-000000000087", second)
}

func completeIdentityRotation(t *testing.T, client *Client, now time.Time, rotationID string, credential []byte) {
	t.Helper()
	client.now = func() time.Time { return now }
	session := &clientSession{client: client, rootContext: context.Background(), send: func(*runnerv1.RunnerMessage) error { return nil }}
	if err := session.handleCredentialRotation(rotationPayload(now, rotationID, credential), now); !errors.Is(err, errCredentialRotationReconnect) {
		t.Fatalf("apply credential rotation %s = %v", rotationID, err)
	}
	if err := client.reconcileCredentialRotationAfterAuthentication(); err != nil {
		t.Fatalf("reconcile credential rotation %s = %v", rotationID, err)
	}
}

func assertPendingRotationRestartReconciles(t *testing.T, configPath, journalPath string, now time.Time, rotationID string, credential []byte) {
	t.Helper()
	restartedConfig, err := LoadConfig(configPath, "test")
	if err != nil || !bytes.Equal(restartedConfig.credential, credential) {
		t.Fatalf("pending second rotation restart credential=%q err=%v", restartedConfig.credential, err)
	}
	restarted, err := newClientWithWorker(restartedConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return now }
	if err := restarted.reconcileCredentialRotationAfterAuthentication(); err != nil {
		t.Fatalf("authenticated second pending reconciliation = %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	reconciled, err := openJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	state := reconciled.snapshot()
	if state.CredentialRotation != nil || state.CommittedCredential == nil || state.CommittedCredential.RunnerID != testRunnerID ||
		state.CommittedCredential.RotationID != rotationID || !bytes.Equal(state.CommittedCredential.Fingerprint, sha256Digest(credential)) {
		t.Fatalf("reconciled second rotation journal = %#v", state)
	}
	if _, err := LoadConfig(configPath, "test"); err != nil {
		t.Fatalf("post-second-reconciliation restart lost committed binding: %v", err)
	}
}
