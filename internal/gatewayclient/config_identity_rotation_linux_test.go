//go:build linux

package gatewayclient

import (
	"bytes"
	"context"
	"errors"
	"os"
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
