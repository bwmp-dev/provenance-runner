package gatewayclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/pluginname"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

const (
	journalSchemaVersion = "provenance.runner-journal/v1alpha1"
	maximumJournalBytes  = 256 << 10
)

type journalJob struct {
	Specification        []byte            `json:"specification"`
	OfferMessageID       string            `json:"offerMessageId"`
	OfferDigest          []byte            `json:"offerDigest"`
	Phase                runnerv1.JobPhase `json:"phase"`
	ExpiresAt            time.Time         `json:"expiresAt"`
	CancellationID       string            `json:"cancellationId,omitempty"`
	CancellationDeadline time.Time         `json:"cancellationDeadline,omitempty"`
	CancellationDigest   []byte            `json:"cancellationDigest,omitempty"`
}

type journalState struct {
	SchemaVersion      string                     `json:"schemaVersion"`
	MessageSequence    uint64                     `json:"messageSequence"`
	HeartbeatSequence  uint64                     `json:"heartbeatSequence"`
	Active             *journalJob                `json:"active,omitempty"`
	PendingMessage     []byte                     `json:"pendingMessage,omitempty"`
	PendingHeartbeat   []byte                     `json:"pendingHeartbeat,omitempty"`
	CredentialRotation *journalCredentialRotation `json:"credentialRotation,omitempty"`
}

type journalCredentialRotation struct {
	RotationID      string    `json:"rotationId"`
	Fingerprint     []byte    `json:"fingerprint"`
	IssuedAt        time.Time `json:"issuedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
	ReconnectBefore time.Time `json:"reconnectBefore"`
	PersistedAt     time.Time `json:"persistedAt,omitempty"`
}

type journal struct {
	mu    sync.Mutex
	path  string
	state journalState
}

func openJournal(path string) (*journal, error) {
	value := &journal{path: path, state: journalState{SchemaVersion: journalSchemaVersion}}
	if path == "" {
		return value, nil
	}
	data, err := readRegularFile(path, maximumJournalBytes, true)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create runner journal directory: %w", err)
		}
		if _, err := value.persistLocked(); err != nil {
			return nil, err
		}
		return value, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read runner journal: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value.state); err != nil {
		return nil, fmt.Errorf("decode runner journal: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode runner journal: multiple JSON values are not allowed")
	}
	if err := validateJournalState(value.state); err != nil {
		return nil, fmt.Errorf("validate runner journal: %w", err)
	}
	return value, nil
}

func validateJournalState(state journalState) error {
	if state.SchemaVersion != journalSchemaVersion {
		return fmt.Errorf("schemaVersion must be %q", journalSchemaVersion)
	}
	if rotation := state.CredentialRotation; rotation != nil {
		if validateUUID("credential rotationId", rotation.RotationID) != nil || rotation.RotationID != strings.ToLower(rotation.RotationID) || len(rotation.Fingerprint) != sha256.Size ||
			rotation.IssuedAt.IsZero() || !rotation.ExpiresAt.After(rotation.IssuedAt) || rotation.ExpiresAt.Sub(rotation.IssuedAt) > time.Hour ||
			!rotation.ReconnectBefore.After(rotation.IssuedAt) || !rotation.ReconnectBefore.Before(rotation.ExpiresAt) || rotation.ReconnectBefore.Sub(rotation.IssuedAt) > 5*time.Minute ||
			(!rotation.PersistedAt.IsZero() && rotation.PersistedAt.Before(rotation.IssuedAt.Add(-maximumClockSkew))) {
			return errors.New("credential rotation state is invalid")
		}
	}
	if len(state.PendingHeartbeat) != 0 {
		heartbeatMessage := new(runnerv1.RunnerMessage)
		if err := proto.Unmarshal(state.PendingHeartbeat, heartbeatMessage); err != nil {
			return fmt.Errorf("decode pending heartbeat: %w", err)
		}
		heartbeat := heartbeatMessage.GetHeartbeat()
		if validateJournalRunnerEnvelope(heartbeatMessage, state.MessageSequence) != nil || heartbeat == nil || heartbeat.GetSequence() == 0 || heartbeat.GetSequence() > state.HeartbeatSequence || len(heartbeat.GetActiveLeases()) > 1 || heartbeat.GetCapacity() == nil || validateTimestamp("heartbeat.observedAt", heartbeat.GetObservedAt()) != nil {
			return errors.New("pending heartbeat is invalid")
		}
	}
	if state.Active == nil {
		if len(state.PendingMessage) == 0 {
			return nil
		}
		message := new(runnerv1.RunnerMessage)
		if err := proto.Unmarshal(state.PendingMessage, message); err != nil {
			return fmt.Errorf("decode pending runner message: %w", err)
		}
		if validateJournalRunnerEnvelope(message, state.MessageSequence) != nil || message.GetLeaseRejected() == nil {
			return errors.New("a pending message without an active job must reject a lease")
		}
		return nil
	}
	if len(state.Active.Specification) == 0 || len(state.Active.Specification) > MaximumMessageBytes {
		return errors.New("active specification is missing or oversized")
	}
	specification := new(runnerv1.JobSpecification)
	if err := proto.Unmarshal(state.Active.Specification, specification); err != nil {
		return fmt.Errorf("decode active specification: %w", err)
	}
	if specification.GetLease() == nil || specification.GetAttempt() == nil || validateTimestamp("active lease expiry", specification.GetLease().GetExpiresAt()) != nil || !state.Active.ExpiresAt.Equal(specification.GetLease().GetExpiresAt().AsTime()) {
		return errors.New("active specification identity or expiry is invalid")
	}
	for field, value := range map[string]string{
		"leaseId": specification.GetLease().GetLeaseId(), "jobId": specification.GetLease().GetJobId(), "executionId": specification.GetLease().GetExecutionId(),
		"attemptId": specification.GetAttempt().GetAttemptId(), "releaseCandidateId": specification.GetAttempt().GetReleaseCandidateId(), "matrixEntryId": specification.GetAttempt().GetMatrixEntryId(),
	} {
		if validateUUID(field, value) != nil {
			return errors.New("active specification identity or expiry is invalid")
		}
	}
	if specification.GetAttempt().GetAttemptNumber() == 0 || specification.GetAttempt().GetAttemptNumber() > maximumAttemptNumber || !pluginname.ValidPaper(specification.GetTargetPluginName()) {
		return errors.New("active specification attempt or target plugin identity is invalid")
	}
	for _, dependency := range specification.GetDependencies() {
		if dependency == nil || !pluginname.ValidPaper(dependency.GetPluginName()) {
			return errors.New("active specification dependency plugin identity is invalid")
		}
	}
	if validateIdentifier("offer messageId", state.Active.OfferMessageID, maximumIdentifierBytes) != nil || len(state.Active.OfferDigest) != sha256.Size {
		return errors.New("active offer identity or digest is invalid")
	}
	switch state.Active.Phase {
	case runnerv1.JobPhase_JOB_PHASE_ACCEPTED, runnerv1.JobPhase_JOB_PHASE_PREPARING, runnerv1.JobPhase_JOB_PHASE_RUNNING, runnerv1.JobPhase_JOB_PHASE_CANCELLING:
	default:
		return errors.New("active phase is invalid")
	}
	if state.Active.CancellationID == "" {
		if len(state.Active.CancellationDigest) != 0 || !state.Active.CancellationDeadline.IsZero() {
			return errors.New("cancellation journal fields require a cancellation ID")
		}
	} else if len(state.Active.CancellationDigest) == 0 {
		if !state.Active.CancellationDeadline.IsZero() {
			return errors.New("authoritative cancellation without a command cannot have command payload fields")
		}
	} else if len(state.Active.CancellationDigest) != sha256.Size || state.Active.CancellationDeadline.IsZero() {
		return errors.New("cancellation command digest and deadline are required")
	}
	if state.Active.CancellationID != "" && validateIdentifier("cancellationId", state.Active.CancellationID, maximumIdentifierBytes) != nil {
		return errors.New("active cancellation ID is invalid")
	}
	if len(state.PendingMessage) != 0 {
		message := new(runnerv1.RunnerMessage)
		if err := proto.Unmarshal(state.PendingMessage, message); err != nil {
			return fmt.Errorf("decode pending runner message: %w", err)
		}
		if validateJournalRunnerEnvelope(message, state.MessageSequence) != nil || !durableRunnerMessage(message) {
			return errors.New("pending runner message is not a durable lease event")
		}
		if message.GetLeaseRejected() == nil {
			lease, attempt := runnerMessageIdentity(message)
			if !activeMatchesIdentity(state.Active, lease, attempt) {
				return errors.New("pending runner event does not match the active lease")
			}
		}
	}
	return nil
}

func validateJournalRunnerEnvelope(message *runnerv1.RunnerMessage, messageSequence uint64) error {
	if message == nil || validateIdentifier("runner messageId", message.GetMessageId(), maximumIdentifierBytes) != nil || validateTimestamp("runner sentAt", message.GetSentAt()) != nil || proto.Size(message) > MaximumMessageBytes {
		return errors.New("runner message envelope is invalid")
	}
	separator := strings.LastIndexByte(message.GetMessageId(), '-')
	if separator < 0 || len(message.GetMessageId())-separator-1 != 16 {
		return errors.New("runner message sequence suffix is invalid")
	}
	sequence, err := strconv.ParseUint(message.GetMessageId()[separator+1:], 16, 64)
	if err != nil || sequence == 0 || sequence > messageSequence {
		return errors.New("runner message sequence exceeds the journal counter")
	}
	return nil
}

func durableRunnerMessage(message *runnerv1.RunnerMessage) bool {
	return message.GetLeaseAccepted() != nil || message.GetLeaseRejected() != nil || message.GetLeaseRenewal() != nil || message.GetJobPreparing() != nil || message.GetJobStarted() != nil || message.GetCompleted() != nil || message.GetFailed() != nil || message.GetCancelled() != nil
}

func (j *journal) snapshot() journalState {
	j.mu.Lock()
	defer j.mu.Unlock()
	return cloneJournalState(j.state)
}

func cloneJournalState(state journalState) journalState {
	cloned := state
	cloned.PendingMessage = bytes.Clone(state.PendingMessage)
	cloned.PendingHeartbeat = bytes.Clone(state.PendingHeartbeat)
	if state.CredentialRotation != nil {
		rotation := *state.CredentialRotation
		rotation.Fingerprint = bytes.Clone(state.CredentialRotation.Fingerprint)
		cloned.CredentialRotation = &rotation
	}
	if state.Active != nil {
		active := *state.Active
		active.Specification = bytes.Clone(state.Active.Specification)
		active.OfferDigest = bytes.Clone(state.Active.OfferDigest)
		active.CancellationDigest = bytes.Clone(state.Active.CancellationDigest)
		cloned.Active = &active
	}
	return cloned
}

func (j *journal) update(update func(*journalState) error) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	previous := cloneJournalState(j.state)
	if err := update(&j.state); err != nil {
		return err
	}
	if err := validateJournalState(j.state); err != nil {
		j.state = previous
		return err
	}
	committed, err := j.persistLocked()
	if err != nil {
		if !committed {
			j.state = previous
		}
		return err
	}
	return nil
}

func (j *journal) nextMessageSequence() (uint64, error) {
	var sequence uint64
	err := j.update(func(state *journalState) error {
		if state.MessageSequence == ^uint64(0) {
			return errors.New("runner message sequence is exhausted")
		}
		state.MessageSequence++
		sequence = state.MessageSequence
		return nil
	})
	return sequence, err
}

func (j *journal) nextHeartbeatSequence() (uint64, error) {
	var sequence uint64
	err := j.update(func(state *journalState) error {
		if state.HeartbeatSequence == ^uint64(0) {
			return errors.New("heartbeat sequence is exhausted")
		}
		state.HeartbeatSequence++
		sequence = state.HeartbeatSequence
		return nil
	})
	return sequence, err
}

func (j *journal) persistLocked() (bool, error) {
	if j.path == "" {
		return true, nil
	}
	data, err := json.Marshal(j.state)
	if err != nil {
		return false, fmt.Errorf("encode runner journal: %w", err)
	}
	if len(data) > maximumJournalBytes {
		return false, fmt.Errorf("runner journal exceeds %d bytes", maximumJournalBytes)
	}
	directory := filepath.Dir(j.path)
	temporary, err := os.CreateTemp(directory, ".provenance-runner-journal-*")
	if err != nil {
		return false, fmt.Errorf("create runner journal: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		temporary.Close()
		if removeTemporary {
			os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, fmt.Errorf("secure runner journal: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return false, fmt.Errorf("write runner journal: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return false, fmt.Errorf("sync runner journal: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("close runner journal: %w", err)
	}
	if existing, err := os.Lstat(j.path); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() || !privateFileMode(existing.Mode().Perm()) {
			return false, errors.New("replace runner journal: existing path is not a private regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect runner journal: %w", err)
	}
	if err := os.Rename(temporaryPath, j.path); err != nil {
		return false, fmt.Errorf("replace runner journal: %w", err)
	}
	removeTemporary = false
	directoryFile, err := os.Open(directory)
	if err != nil {
		return true, fmt.Errorf("open runner journal directory: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return true, fmt.Errorf("sync runner journal directory: %w", err)
	}
	return true, nil
}
