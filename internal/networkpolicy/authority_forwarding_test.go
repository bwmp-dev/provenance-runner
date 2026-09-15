package networkpolicy

import (
	"bytes"
	"context"
	"testing"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthorityControlUpdatesAreCurrentCopiedAndOrdered(t *testing.T) {
	s, receipt, features, expiry, _, _ := authorityRouteFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Reconcile(ctx, receipt, features, expiry); err != nil {
		t.Fatal(err)
	}
	sequence, raw, err := s.NextControlUpdate(ctx, 0)
	if err != nil || sequence != 1 {
		t.Fatal("initial authority", sequence, err)
	}
	update, err := DecodeAuthorityUpdate(raw)
	if err != nil || !proto.Equal(update.Reconciliation, receipt) {
		t.Fatal("wrong retained reconciliation", err)
	}
	raw[0] ^= 1
	_, again, err := s.NextControlUpdate(ctx, 0)
	if err != nil || bytes.Equal(raw, again) {
		t.Fatal("mutable history")
	}
	older := proto.Clone(receipt).(*p.LeaseReconciliation)
	for _, seconds := range []int{12, 30} {
		receipt.NetworkAuthorityV2.CheckedAt = timestamppb.New(time.Now())
		receipt.NetworkAuthorityV2.ExpiresAt = timestamppb.New(time.Now().Add(time.Duration(seconds) * time.Second))
		if err := s.Reconcile(ctx, receipt, features, expiry); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Reconcile(ctx, older, features, expiry); err != nil {
		t.Fatal("older valid acknowledgement", err)
	}
	for expected := uint64(2); expected <= 3; expected++ {
		next, raw, err := s.NextControlUpdate(ctx, sequence)
		if err != nil || next != expected {
			t.Fatal("update skipped", next, err)
		}
		update, err := DecodeAuthorityUpdate(raw)
		if err != nil {
			t.Fatal(err)
		}
		remaining := time.Until(update.Reconciliation.NetworkAuthorityV2.ExpiresAt.AsTime())
		if expected == 2 && remaining > 12*time.Second {
			t.Fatal("deadline reduction skipped")
		}
		sequence = next
	}
	if latest, _, err := s.NextControlUpdate(ctx, 0); err != nil || latest != 3 {
		t.Fatal("older acknowledgement replaced latest grant", latest, err)
	}
}

func TestAuthorityControlWaitingCancellationAndWithdrawal(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		s, receipt, features, expiry, _, _ := authorityRouteFixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := s.Reconcile(ctx, receipt, features, expiry); err != nil {
			t.Fatal(err)
		}
		sequence, _, err := s.NextControlUpdate(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, _, err := s.NextControlUpdate(ctx, sequence); done <- err }()
		if withdraw {
			_ = s.Withdraw()
		} else {
			cancel()
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("stopped waiter received authority")
			}
		case <-time.After(time.Second):
			t.Fatal("waiter did not stop")
		}
		cancel()
	}
}

func TestAuthorityControlLagAndFutureCursorNeverResume(t *testing.T) {
	for _, future := range []bool{false, true} {
		s, receipt, features, expiry, _, _ := authorityRouteFixture(t)
		ctx := context.Background()
		for i := 0; i < maximumControlUpdates+2; i++ {
			if err := s.Reconcile(ctx, receipt, features, expiry); err != nil {
				t.Fatal(err)
			}
		}
		if len(s.controlUpdates) != maximumControlUpdates {
			t.Fatal("unbounded history")
		}
		cursor := uint64(1)
		if future {
			cursor = s.controlSequence + 1
		}
		if _, _, err := s.NextControlUpdate(ctx, cursor); err == nil {
			t.Fatal("invalid cursor skipped updates")
		}
		if _, _, err := s.NextControlUpdate(ctx, 0); err == nil {
			t.Fatal("failed forwarding resumed")
		}
		select {
		case <-s.Done():
		default:
			t.Fatal("forwarding loss did not withdraw authority")
		}
	}
}

func TestAuthorityControlWaiterReceivesFreshUpdateWithoutCapabilities(t *testing.T) {
	s, receipt, features, expiry, _, _ := authorityRouteFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Reconcile(ctx, receipt, features, expiry); err != nil {
		t.Fatal(err)
	}
	sequence, _, err := s.NextControlUpdate(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	type received struct {
		sequence uint64
		raw      []byte
		err      error
	}
	done := make(chan received, 1)
	go func() {
		next, raw, err := s.NextControlUpdate(ctx, sequence)
		done <- received{next, raw, err}
	}()
	receipt.CompleteLogUpload = &p.ObjectUpload{Uri: "https://object.example/?synthetic-private-upload", ExpiresAt: timestamppb.New(expiry), ObjectKey: "data/logs/fixture.gz"}
	receipt.NetworkAuthorityV2.CheckedAt = timestamppb.New(time.Now())
	if err := s.Reconcile(ctx, receipt, features, expiry); err != nil {
		t.Fatal(err)
	}
	// Mutation after reconciliation must not rewrite the retained wire bytes.
	receipt.CompleteLogUpload.ObjectKey = "changed"
	select {
	case result := <-done:
		if result.err != nil || result.sequence != sequence+1 {
			t.Fatal("waiter missed update", result.err)
		}
		update, err := DecodeAuthorityUpdate(result.raw)
		if err != nil || update.Reconciliation.CompleteLogUpload.Uri != "" || update.Reconciliation.CompleteLogUpload.ExpiresAt != nil || update.Reconciliation.CompleteLogUpload.ObjectKey != "data/logs/fixture.gz" {
			t.Fatal("mutable or capability-bearing update", err)
		}
	case <-ctx.Done():
		t.Fatal("update did not wake waiter")
	}
}
