//go:build linux

package measuredservice

import (
	"context"
	"sync"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
)

func keepalive(ctx context.Context, send *sender, cancel context.CancelCauseFunc) (context.CancelFunc, <-chan struct{}) {
	keepCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-keepCtx.Done():
				return
			case <-tick.C:
				if send.progress() != nil {
					cancel(ErrService)
					return
				}
			}
		}
	}()
	return stop, done
}

// One sequencer serializes progress, observation, guest relay and completion.
// Guest-controlled bytes can never choose their packet kind or sequence.
type sender struct {
	mu                  sync.Mutex
	channel             *cc.Channel
	sequence            uint64
	observed, completed bool
}

func (s *sender) sendLocked(kind cc.Kind, payload []byte) error {
	if s.completed || s.sequence == ^uint64(0) {
		return cc.ErrChannel
	}
	s.sequence++
	return s.channel.Send(cc.Packet{Kind: kind, Sequence: s.sequence, Payload: payload}, time.Now().Add(5*time.Second))
}

func (s *sender) progress() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kind := cc.Preparing
	if s.observed {
		kind = cc.Result
	}
	return s.sendLocked(kind, nil)
}

func (s *sender) observation(raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.observed {
		return cc.ErrChannel
	}
	if err := s.sendLocked(cc.Observation, raw); err != nil {
		return err
	}
	s.observed = true
	return nil
}

func (s *sender) result(raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.observed {
		return cc.ErrChannel
	}
	return s.sendLocked(cc.Result, raw)
}

func (s *sender) completion(raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.observed {
		return cc.ErrChannel
	}
	err := s.sendLocked(cc.Completion, raw)
	s.completed = true
	return err
}
