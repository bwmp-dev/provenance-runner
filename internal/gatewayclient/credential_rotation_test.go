package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func canonicalCredential(fill byte) []byte {
	return []byte("prc_v1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, sha256.Size)))
}

func rotationPayload(now time.Time, rotationID string, credential []byte) *runnerv1.RotateCredential {
	fingerprint := sha256.Sum256(credential)
	return &runnerv1.RotateCredential{
		RotationId: rotationID, ConnectionCredential: bytes.Clone(credential), CredentialFingerprint: bytes.Clone(fingerprint[:]),
		IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(15 * time.Minute)), ReconnectBefore: timestamppb.New(now.Add(2 * time.Minute)),
	}
}

func rotationClient(t *testing.T, credential []byte) (*Client, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "credential")
	if err := os.WriteFile(path, credential, 0o600); err != nil {
		t.Fatal(err)
	}
	config := validConfig()
	config.CredentialFile = path
	config.credential = bytes.Clone(credential)
	config.journalFile = filepath.Join(directory, "journal.json")
	client, err := newClientWithWorker(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, path
}

func TestCredentialRotationCapabilityRequiresDurableStore(t *testing.T) {
	legacy := newClient(validConfig(), nil)
	if features := legacy.capabilities().GetFeatures(); len(features) != 1 || features[0] != runnerv1.ProtocolFeature_PROTOCOL_FEATURE_DURABLE_LEASE_ACKNOWLEDGEMENTS {
		t.Fatalf("legacy features = %v", features)
	}
	capable, _ := rotationClient(t, canonicalCredential(1))
	features := capable.capabilities().GetFeatures()
	if len(features) != 2 || features[1] != runnerv1.ProtocolFeature_PROTOCOL_FEATURE_CREDENTIAL_ROTATION {
		t.Fatalf("rotation-capable features = %v", features)
	}
	directory := t.TempDir()
	credentialPath := filepath.Join(directory, "read-only-credential")
	if err := os.WriteFile(credentialPath, canonicalCredential(1), 0o400); err != nil {
		t.Fatal(err)
	}
	incapableConfig := validConfig()
	incapableConfig.CredentialFile = credentialPath
	incapableConfig.credential = canonicalCredential(1)
	incapableConfig.journalFile = filepath.Join(directory, "journal.json")
	incapable, err := newClientWithWorker(incapableConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer incapable.Close()
	if features := incapable.capabilities().GetFeatures(); len(features) != 1 || features[0] != runnerv1.ProtocolFeature_PROTOCOL_FEATURE_DURABLE_LEASE_ACKNOWLEDGEMENTS {
		t.Fatalf("incapable store changed legacy features = %v", features)
	}
}

func TestCredentialRotationPersistsBeforeAcknowledgementAndExactReplayIsIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	client, credentialPath := rotationClient(t, canonicalCredential(1))
	client.now = func() time.Time { return now }
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{client: client, rootContext: context.Background(), send: func(message *runnerv1.RunnerMessage) error {
		persisted, err := os.ReadFile(credentialPath)
		if err != nil || !bytes.Equal(persisted, canonicalCredential(2)) || client.journal.snapshot().CredentialRotation.PersistedAt.IsZero() {
			t.Fatalf("acknowledgement preceded persistence: %q, %v", persisted, err)
		}
		sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}}
	rotationID := "60000000-0000-4000-8000-000000000001"
	payload := rotationPayload(now, rotationID, canonicalCredential(2))
	if err := session.handleCredentialRotation(payload, now); !errors.Is(err, errCredentialRotationReconnect) {
		t.Fatalf("rotation result = %v", err)
	}
	if len(sent) != 1 || sent[0].GetCredentialRotationAcknowledgement().GetRotationId() != rotationID ||
		!bytes.Equal(sent[0].GetCredentialRotationAcknowledgement().GetCredentialFingerprint(), sha256Digest(canonicalCredential(2))) {
		t.Fatalf("rotation acknowledgement = %#v", sent)
	}
	persistedAt := sent[0].GetCredentialRotationAcknowledgement().GetPersistedAt().AsTime()
	if err := session.handleCredentialRotation(rotationPayload(now, rotationID, canonicalCredential(2)), now.Add(time.Second)); !errors.Is(err, errCredentialRotationReconnect) {
		t.Fatalf("exact replay = %v", err)
	}
	if len(sent) != 2 || !sent[1].GetCredentialRotationAcknowledgement().GetPersistedAt().AsTime().Equal(persistedAt) {
		t.Fatal("exact replay changed durable acknowledgement identity")
	}
	conflict := rotationPayload(now, rotationID, canonicalCredential(2))
	conflict.ExpiresAt = timestamppb.New(now.Add(14 * time.Minute))
	if err := session.handleCredentialRotation(conflict, now.Add(time.Second)); err == nil || transient(err) || strings.Contains(err.Error(), string(canonicalCredential(2))) {
		t.Fatalf("conflicting replay result = %v", err)
	}
	data, _ := os.ReadFile(credentialPath)
	if !bytes.Equal(data, canonicalCredential(2)) {
		t.Fatal("conflicting replay changed the durable credential")
	}
}

func TestCredentialRotationAckSendAmbiguityReconnectAndRestart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	client, credentialPath := rotationClient(t, canonicalCredential(3))
	journalPath := client.config.journalFile
	rotationID := "60000000-0000-4000-8000-000000000002"
	session := &clientSession{client: client, rootContext: context.Background(), send: func(*runnerv1.RunnerMessage) error { return io.EOF }}
	if err := session.handleCredentialRotation(rotationPayload(now, rotationID, canonicalCredential(4)), now); !errors.Is(err, io.EOF) {
		t.Fatalf("ambiguous acknowledgement send = %v", err)
	}
	if client.journal.snapshot().CredentialRotation == nil {
		t.Fatal("ack-send ambiguity discarded reconnect state")
	}
	_ = client.Close()
	configPath := filepath.Join(filepath.Dir(credentialPath), "connect.json")
	if err := os.WriteFile(configPath, []byte(validConfigJSON("credential")), 0o600); err != nil {
		t.Fatal(err)
	}
	restartedConfig, err := LoadConfig(configPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	restartedConfig.journalFile = journalPath
	restarted, err := newClientWithWorker(restartedConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if !bytes.Equal(restarted.config.credential, canonicalCredential(4)) || restarted.journal.snapshot().CredentialRotation == nil {
		t.Fatal("restart did not load the replacement and reconnect state")
	}
	if err := restarted.reconcileCredentialRotationAfterAuthentication(); err != nil {
		t.Fatal(err)
	}
	if restarted.journal.snapshot().CredentialRotation != nil {
		t.Fatal("successful new-credential authentication did not finalize reconnect state")
	}
}

func TestCredentialRotationForcesImmediateReconnectWithNewCredential(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	oldCredential := canonicalCredential(6)
	newCredential := canonicalCredential(7)
	client, _ := rotationClient(t, oldCredential)
	first := newScriptedStream(context.Background(),
		authenticatedMessage(now, platformScope()),
		gatewayMessage(now, &runnerv1.GatewayMessage_CredentialRotation{CredentialRotation: rotationPayload(now, "60000000-0000-4000-8000-000000000004", newCredential)}),
	)
	second := newScriptedStream(context.Background(),
		authenticatedMessage(now, platformScope()),
		gatewayMessage(now, &runnerv1.GatewayMessage_Shutdown{Shutdown: &runnerv1.ShutdownRunner{ShutdownId: "shutdown", Deadline: timestamppb.New(now.Add(time.Minute))}}),
	)
	client.connector = &scriptedConnector{results: []connectResult{{stream: first}, {stream: second}}}
	client.now = func() time.Time { return now }
	var waits []time.Duration
	client.wait = func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		return nil
	}
	if err := client.Run(context.Background()); !errors.Is(err, ErrServerShutdown) {
		t.Fatalf("runner result = %v", err)
	}
	first.mu.Lock()
	firstSent := append([]*runnerv1.RunnerMessage(nil), first.sent...)
	first.mu.Unlock()
	second.mu.Lock()
	secondSent := append([]*runnerv1.RunnerMessage(nil), second.sent...)
	second.mu.Unlock()
	if len(firstSent) < 4 || !bytes.Equal(firstSent[0].GetAuthenticate().GetConnectionCredential(), oldCredential) || firstSent[len(firstSent)-1].GetCredentialRotationAcknowledgement() == nil {
		t.Fatalf("first session messages = %#v", firstSent)
	}
	if len(secondSent) < 1 || !bytes.Equal(secondSent[0].GetAuthenticate().GetConnectionCredential(), newCredential) {
		t.Fatalf("reconnect authenticate = %#v", secondSent)
	}
	if len(waits) != 0 {
		t.Fatalf("credential reconnect was delayed: %v", waits)
	}
	if client.journal.snapshot().CredentialRotation != nil {
		t.Fatal("authenticated reconnect retained completed rotation state")
	}
}

func TestCredentialRotationReconnectDeadlineCancelsBlockedAcknowledgement(t *testing.T) {
	now := time.Now().UTC()
	client, credentialPath := rotationClient(t, canonicalCredential(8))
	sessionContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &clientSession{
		client: client, rootContext: context.Background(), cancelSession: cancel,
		send: func(*runnerv1.RunnerMessage) error {
			<-sessionContext.Done()
			return sessionContext.Err()
		},
	}
	payload := rotationPayload(now, "60000000-0000-4000-8000-000000000005", canonicalCredential(9))
	payload.ReconnectBefore = timestamppb.New(now.Add(25 * time.Millisecond))
	payload.ExpiresAt = timestamppb.New(now.Add(time.Minute))
	started := time.Now()
	if err := session.handleCredentialRotation(payload, now); !errors.Is(err, errCredentialRotationReconnect) {
		t.Fatalf("blocked acknowledgement result = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("reconnect deadline was not bounded: %s", elapsed)
	}
	persisted, err := os.ReadFile(credentialPath)
	if err != nil || !bytes.Equal(persisted, canonicalCredential(9)) {
		t.Fatalf("deadline interrupted durable persistence: %q, %v", persisted, err)
	}
}

func TestCredentialRotationValidationRejectsMalformedBoundsWithoutSecretReflection(t *testing.T) {
	now := time.Now().UTC()
	valid := func() *runnerv1.RotateCredential {
		return rotationPayload(now, "60000000-0000-4000-8000-000000000003", canonicalCredential(5))
	}
	for name, mutate := range map[string]func(*runnerv1.RotateCredential){
		"uppercase id":      func(value *runnerv1.RotateCredential) { value.RotationId = "60000000-0000-4000-8000-00000000000A" },
		"wrong size":        func(value *runnerv1.RotateCredential) { value.ConnectionCredential = []byte("prc_v1_secret") },
		"wrong fingerprint": func(value *runnerv1.RotateCredential) { value.CredentialFingerprint[0] ^= 1 },
		"missing issued":    func(value *runnerv1.RotateCredential) { value.IssuedAt = nil },
		"long ttl": func(value *runnerv1.RotateCredential) {
			value.ExpiresAt = timestamppb.New(now.Add(time.Hour + time.Second))
		},
		"late reconnect": func(value *runnerv1.RotateCredential) {
			value.ReconnectBefore = timestamppb.New(now.Add(5*time.Minute + time.Second))
		},
		"past reconnect": func(value *runnerv1.RotateCredential) { value.ReconnectBefore = timestamppb.New(now) },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid()
			mutate(value)
			if _, credential, err := validateCredentialRotation(value, now); err == nil || credential != nil || strings.Contains(err.Error(), string(value.GetConnectionCredential())) {
				t.Fatalf("validation = %q, %v", credential, err)
			}
		})
	}
	legacy := newClient(validConfig(), nil)
	unnegotiated := valid()
	secretLength := len(unnegotiated.ConnectionCredential)
	if err := (&clientSession{client: legacy}).handleCredentialRotation(unnegotiated, now); err == nil || transient(err) {
		t.Fatalf("unnegotiated rotation result = %v", err)
	}
	if !bytes.Equal(unnegotiated.ConnectionCredential, make([]byte, secretLength)) {
		t.Fatal("unnegotiated credential payload was not cleared")
	}
}

func sha256Digest(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}
