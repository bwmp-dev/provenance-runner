package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestJournalPersistsExactPendingBytesAndCounters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose the owner-only journal mode used by connect mode")
	}
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "journal.json")
	journal, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if sequence, err := journal.nextMessageSequence(); err != nil || sequence != 1 {
		t.Fatalf("next message sequence = %d, %v", sequence, err)
	}
	if sequence, err := journal.nextHeartbeatSequence(); err != nil || sequence != 1 {
		t.Fatalf("next heartbeat sequence = %d, %v", sequence, err)
	}
	offer := validLeaseOffer(now)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.GetJob())
	if err != nil {
		t.Fatal(err)
	}
	pendingMessage := &runnerv1.RunnerMessage{
		MessageId: "000000000000000000000000-0000000000000001",
		SentAt:    timestamppb.New(now),
		Payload: &runnerv1.RunnerMessage_LeaseAccepted{LeaseAccepted: &runnerv1.LeaseAccepted{
			Lease: offer.GetJob().GetLease(), Attempt: offer.GetJob().GetAttempt(), AcceptedAt: timestamppb.New(now),
		}},
	}
	pending, err := proto.MarshalOptions{Deterministic: true}.Marshal(pendingMessage)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer-1", OfferDigest: bytes.Repeat([]byte{1}, sha256.Size), Phase: runnerv1.JobPhase_JOB_PHASE_CANCELLING, ExpiresAt: offer.GetJob().GetLease().GetExpiresAt().AsTime(), CancellationID: "cancellation-1", CancellationDeadline: now.Add(time.Minute), CancellationDigest: bytes.Repeat([]byte{2}, sha256.Size)}
		state.PendingMessage = pending
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	reopened, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := reopened.snapshot()
	if snapshot.MessageSequence != 1 || snapshot.HeartbeatSequence != 1 || !bytes.Equal(snapshot.PendingMessage, pending) {
		t.Fatalf("reopened journal = %#v", snapshot)
	}
	if !bytes.Equal(snapshot.Active.CancellationDigest, bytes.Repeat([]byte{2}, sha256.Size)) {
		t.Fatalf("reopened cancellation identity = %#v", snapshot.Active)
	}
	decoded := new(runnerv1.RunnerMessage)
	if err := proto.Unmarshal(snapshot.PendingMessage, decoded); err != nil || !proto.Equal(decoded, pendingMessage) {
		t.Fatalf("pending message = %#v, %v", decoded, err)
	}
	if sequence, err := reopened.nextMessageSequence(); err != nil || sequence != 2 {
		t.Fatalf("restarted message sequence = %d, %v", sequence, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".provenance-runner-journal-") {
			t.Fatalf("atomic journal temporary file remained: %s", entry.Name())
		}
	}
}

func TestJournalRejectsCorruptAndInconsistentState(t *testing.T) {
	if err := validateJournalState(journalState{SchemaVersion: "wrong"}); err == nil {
		t.Fatal("wrong journal schema accepted")
	}
	if err := validateJournalState(journalState{SchemaVersion: journalSchemaVersion, PendingMessage: []byte("not protobuf")}); err == nil {
		t.Fatal("corrupt pending message accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	path := filepath.Join(t.TempDir(), "journal.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openJournal(path); err == nil || !strings.Contains(err.Error(), "decode runner journal") {
		t.Fatalf("open corrupt journal error = %v", err)
	}
}

func TestHeartbeatIsCommittedBeforeSendAndReplayedExactlyAcrossProcessReopen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose the owner-only journal mode used by connect mode")
	}
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	config := validConfig()
	config.journalFile = filepath.Join(t.TempDir(), "journal.json")
	newSession := func(client *Client, sent *[][]byte) *clientSession {
		return &clientSession{
			client:        client,
			authenticated: authenticatedMessage(now, platformScope()).GetAuthenticated(),
			rootContext:   context.Background(),
			send: func(message *runnerv1.RunnerMessage) error {
				encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
				if err == nil {
					*sent = append(*sent, encoded)
				}
				return err
			},
		}
	}
	first, err := newClientWithWorker(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	first.now = func() time.Time { return now }
	var firstSent [][]byte
	firstSession := newSession(first, &firstSent)
	if err := firstSession.sendHeartbeat(now); err != nil {
		t.Fatal(err)
	}
	committed := first.journal.snapshot().PendingHeartbeat
	if len(firstSent) != 1 || !bytes.Equal(firstSent[0], committed) {
		t.Fatal("heartbeat was not committed exactly before send")
	}

	second, err := newClientWithWorker(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second.now = func() time.Time { return now.Add(time.Minute) }
	var secondSent [][]byte
	secondSession := newSession(second, &secondSent)
	if err := secondSession.sendHeartbeat(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(secondSent) != 1 || !bytes.Equal(secondSent[0], committed) {
		t.Fatal("process reopen did not replay the exact pending heartbeat")
	}
	replayed := secondSession.pendingHeartbeat
	conflicting := &runnerv1.HeartbeatAcknowledgement{RunnerMessageId: "another-message", Sequence: replayed.GetHeartbeat().GetSequence(), CommittedAt: timestamppb.New(now.Add(time.Minute))}
	if err := secondSession.handleHeartbeatAcknowledgement(conflicting, now.Add(time.Minute)); err == nil || !bytes.Equal(second.journal.snapshot().PendingHeartbeat, committed) {
		t.Fatalf("conflicting heartbeat acknowledgement = %v", err)
	}
	acknowledgement := &runnerv1.HeartbeatAcknowledgement{RunnerMessageId: replayed.GetMessageId(), Sequence: replayed.GetHeartbeat().GetSequence(), CommittedAt: timestamppb.New(now.Add(time.Minute))}
	if err := secondSession.handleHeartbeatAcknowledgement(acknowledgement, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	third, err := newClientWithWorker(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := third.journal.snapshot()
	if len(snapshot.PendingHeartbeat) != 0 || snapshot.HeartbeatSequence != 1 || snapshot.MessageSequence != 1 {
		t.Fatalf("acknowledged heartbeat journal = %#v", snapshot)
	}
}
