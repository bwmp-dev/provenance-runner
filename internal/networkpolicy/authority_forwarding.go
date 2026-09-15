package networkpolicy

import (
	"bytes"
	"context"
	"errors"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

const maximumControlUpdates = 64

type authorityControlUpdate struct {
	sequence uint64
	payload  []byte
}

// Called only after successful reconciliation and any installed-route refresh.
// Encoding failure disables forwarding without changing existing local-route
// semantics. A remote execution must fail closed if this feed is unavailable.
func (s *AuthorityRoute) recordControlUpdateLocked(value *p.LeaseReconciliation, features []p.ProtocolFeature, expiry time.Time) {
	if s.controlUnavailable {
		return
	}
	checked := value.GetNetworkAuthorityV2().GetCheckedAt().AsTime()
	if checked.Before(s.controlChecked) {
		// Older accepted observations cannot replace the latest current grant
		// when a newly connected root consumer obtains its initial update.
		return
	}
	raw, err := EncodeAuthorityUpdate(AuthorityUpdate{Reconciliation: value, Features: features, CredentialExpiry: expiry})
	if err != nil || s.controlSequence == ^uint64(0) {
		s.controlUnavailable = true
		s.controlUpdates = nil
	} else {
		s.controlSequence++
		s.controlChecked = checked
		s.controlUpdates = append(s.controlUpdates, authorityControlUpdate{s.controlSequence, raw})
		if len(s.controlUpdates) > maximumControlUpdates {
			s.controlUpdates[0] = authorityControlUpdate{}
			s.controlUpdates = s.controlUpdates[1:]
		}
	}
	close(s.controlChanged)
	s.controlChanged = make(chan struct{})
}

// NextControlUpdate copies a bounded, capability-stripped reconciliation from
// this live supervisor. The caller must first CheckJob for its exact attempt.
// after=0 obtains the latest current update; thereafter pass the returned cursor
// to consume every subsequent recorded update in order. Falling behind the
// bounded history refuses rather than skipping deadline reductions. This is not
// stream authentication, persistence, permission renewal, or a resumable grant.
func (s *AuthorityRoute) NextControlUpdate(ctx context.Context, after uint64) (uint64, []byte, error) {
	if s == nil || ctx == nil {
		return 0, nil, ErrAuthority
	}
	for {
		s.mu.Lock()
		if ctx.Err() != nil || s.ctx == nil || s.ctx.Err() != nil || s.withdrawn || s.controlUnavailable || s.authority == nil || s.controlChanged == nil {
			s.mu.Unlock()
			return 0, nil, errors.Join(ErrAuthority, ctx.Err())
		}
		if _, err := s.authority.Deadline(time.Now()); err != nil {
			err = s.withdrawLocked(err)
			s.mu.Unlock()
			return 0, nil, err
		}
		if len(s.controlUpdates) == 0 || after > s.controlSequence {
			err := s.withdrawLocked(ErrAuthority)
			s.mu.Unlock()
			return 0, nil, err
		}
		var update *authorityControlUpdate
		if after == 0 {
			update = &s.controlUpdates[len(s.controlUpdates)-1]
		} else if after < s.controlSequence {
			first := s.controlUpdates[0].sequence
			if after+1 < first {
				err := s.withdrawLocked(ErrAuthority)
				s.mu.Unlock()
				return 0, nil, err
			}
			update = &s.controlUpdates[after+1-first]
		}
		if update != nil {
			sequence, raw := update.sequence, bytes.Clone(update.payload)
			s.mu.Unlock()
			return sequence, raw, nil
		}
		changed, done := s.controlChanged, s.done
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return 0, nil, errors.Join(ErrAuthority, ctx.Err())
		case <-done:
			return 0, nil, ErrAuthorityWithdrawn
		case <-changed:
		}
	}
}
