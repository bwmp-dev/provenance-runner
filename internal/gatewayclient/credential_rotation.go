package gatewayclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"sync/atomic"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var canonicalConnectionCredentialPattern = regexp.MustCompile(`^prc_v1_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`)

var errCredentialRotationReconnect = errors.New("credential rotation requires reconnect")

func (s *clientSession) handleCredentialRotation(rotation *runnerv1.RotateCredential, now time.Time) error {
	if rotation != nil {
		defer clear(rotation.ConnectionCredential)
	}
	if s.client.config.credentialStore == nil {
		return permanent("credential rotation was not negotiated")
	}
	metadata, credential, err := validateCredentialRotation(rotation, now)
	if err != nil {
		return permanent("credential rotation is invalid")
	}
	metadata.RunnerID = s.client.config.RunnerID
	defer clear(credential)
	var reconnectDeadlineExpired atomic.Bool
	var reconnectTimer *time.Timer
	if s.cancelSession != nil {
		reconnectTimer = time.AfterFunc(metadata.ReconnectBefore.Sub(now), func() {
			reconnectDeadlineExpired.Store(true)
			s.cancelSession()
		})
		defer reconnectTimer.Stop()
	}
	if err := s.client.journal.update(func(state *journalState) error {
		if state.CredentialRotation == nil {
			state.CredentialRotation = metadata
			return nil
		}
		if !sameCredentialRotation(state.CredentialRotation, metadata) {
			return errors.New("credential rotation identity conflicts with durable state")
		}
		if state.CredentialRotation.RunnerID == "" {
			state.CredentialRotation.RunnerID = metadata.RunnerID
		}
		return nil
	}); err != nil {
		return permanent("credential rotation conflicts with durable state")
	}
	if err := s.client.config.credentialStore.Replace(credential); err != nil {
		return permanent("durable credential replacement failed")
	}
	clear(s.client.config.credential)
	s.client.config.credential = bytes.Clone(credential)
	if err := s.client.journal.update(func(state *journalState) error {
		if state.CredentialRotation == nil || !sameCredentialRotation(state.CredentialRotation, metadata) {
			return errors.New("credential rotation identity changed during persistence")
		}
		if state.CredentialRotation.PersistedAt.IsZero() {
			state.CredentialRotation.PersistedAt = now.UTC()
		}
		state.CommittedCredential = &journalCommittedCredential{
			RunnerID: s.client.config.RunnerID, RotationID: metadata.RotationID, Fingerprint: bytes.Clone(metadata.Fingerprint),
			IssuedAt: metadata.IssuedAt, ExpiresAt: metadata.ExpiresAt, PersistedAt: state.CredentialRotation.PersistedAt,
		}
		return nil
	}); err != nil {
		// The credential itself is already durable. Reconnect without claiming
		// acknowledgement so successful new-credential authentication can safely
		// reconcile an ambiguous journal commit.
		return errCredentialRotationReconnect
	}
	committed := s.client.journal.snapshot().CredentialRotation
	acknowledgement := &runnerv1.CredentialRotationAcknowledgement{
		RotationId: committed.RotationID, CredentialFingerprint: bytes.Clone(committed.Fingerprint), PersistedAt: timestamppb.New(committed.PersistedAt),
	}
	message, err := s.client.runnerMessage()
	if err != nil {
		return err
	}
	message.Payload = &runnerv1.RunnerMessage_CredentialRotationAcknowledgement{CredentialRotationAcknowledgement: acknowledgement}
	if err := s.send(message); err != nil {
		clear(acknowledgement.CredentialFingerprint)
		if reconnectDeadlineExpired.Load() {
			return errCredentialRotationReconnect
		}
		return err
	}
	clear(acknowledgement.CredentialFingerprint)
	return errCredentialRotationReconnect
}

func validateCredentialRotation(rotation *runnerv1.RotateCredential, now time.Time) (*journalCredentialRotation, []byte, error) {
	if rotation == nil || validateUUID("credential rotationId", rotation.GetRotationId()) != nil || rotation.GetRotationId() != string(bytes.ToLower([]byte(rotation.GetRotationId()))) {
		return nil, nil, errors.New("invalid rotation identity")
	}
	credential := bytes.Clone(rotation.GetConnectionCredential())
	if len(credential) != 50 || !canonicalConnectionCredentialPattern.Match(credential) {
		clear(credential)
		return nil, nil, errors.New("invalid credential")
	}
	encoded := credential[len("prc_v1_"):]
	decoded, err := base64.RawURLEncoding.DecodeString(string(encoded))
	if err != nil || len(decoded) != sha256.Size || !bytes.Equal([]byte(base64.RawURLEncoding.EncodeToString(decoded)), encoded) {
		clear(decoded)
		clear(credential)
		return nil, nil, errors.New("invalid credential")
	}
	clear(decoded)
	fingerprint := sha256.Sum256(credential)
	if len(rotation.GetCredentialFingerprint()) != sha256.Size || !bytes.Equal(rotation.GetCredentialFingerprint(), fingerprint[:]) {
		clear(credential)
		return nil, nil, errors.New("invalid fingerprint")
	}
	for _, value := range []*timestamppb.Timestamp{rotation.GetIssuedAt(), rotation.GetExpiresAt(), rotation.GetReconnectBefore()} {
		if validateTimestamp("credential rotation timestamp", value) != nil {
			clear(credential)
			return nil, nil, errors.New("invalid timestamp")
		}
	}
	issuedAt := rotation.GetIssuedAt().AsTime().UTC()
	expiresAt := rotation.GetExpiresAt().AsTime().UTC()
	reconnectBefore := rotation.GetReconnectBefore().AsTime().UTC()
	if issuedAt.After(now.Add(maximumClockSkew)) || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > time.Hour ||
		!reconnectBefore.After(issuedAt) || !reconnectBefore.Before(expiresAt) || reconnectBefore.Sub(issuedAt) > 5*time.Minute || !now.Before(reconnectBefore) {
		clear(credential)
		return nil, nil, errors.New("invalid credential lifetime")
	}
	return &journalCredentialRotation{
		RotationID: rotation.GetRotationId(), Fingerprint: bytes.Clone(fingerprint[:]), IssuedAt: issuedAt, ExpiresAt: expiresAt, ReconnectBefore: reconnectBefore,
	}, credential, nil
}

func sameCredentialRotation(left, right *journalCredentialRotation) bool {
	runnerCompatible := left != nil && right != nil && (left.RunnerID == right.RunnerID || left.RunnerID == "" || right.RunnerID == "")
	return runnerCompatible && left.RotationID == right.RotationID && bytes.Equal(left.Fingerprint, right.Fingerprint) &&
		left.IssuedAt.Equal(right.IssuedAt) && left.ExpiresAt.Equal(right.ExpiresAt) && left.ReconnectBefore.Equal(right.ReconnectBefore)
}

func (c *Client) reconcileCredentialRotationAfterAuthentication() error {
	rotation := c.journal.snapshot().CredentialRotation
	if rotation == nil || sha256.Sum256(c.config.credential) != bytesToDigest(rotation.Fingerprint) {
		return nil
	}
	now := c.now().UTC()
	return c.journal.update(func(state *journalState) error {
		if state.CredentialRotation != nil && sameCredentialRotation(state.CredentialRotation, rotation) {
			if c.config.IdentityKeyFile != "" {
				if rotation.RunnerID != c.config.RunnerID || !now.Before(rotation.ExpiresAt) {
					return errors.New("credential rotation is not bound to this runner")
				}
				if state.CommittedCredential == nil {
					if !rotation.PersistedAt.IsZero() {
						return errors.New("persisted credential rotation lacks a committed binding")
					}
					state.CommittedCredential = &journalCommittedCredential{
						RunnerID: rotation.RunnerID, RotationID: rotation.RotationID, Fingerprint: bytes.Clone(rotation.Fingerprint),
						IssuedAt: rotation.IssuedAt, ExpiresAt: rotation.ExpiresAt, PersistedAt: now,
					}
				}
			}
			state.CredentialRotation = nil
		}
		return nil
	})
}

func bytesToDigest(value []byte) [sha256.Size]byte {
	var digest [sha256.Size]byte
	copy(digest[:], value)
	return digest
}
