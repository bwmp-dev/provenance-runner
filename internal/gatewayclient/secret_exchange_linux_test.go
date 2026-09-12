//go:build linux

package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSecretJournalRestartRetainsOnlyMetadataAndRequiresFreshDelivery(t *testing.T) {
	s, request, _ := secretExchangeFixture(t)
	path := filepath.Join(t.TempDir(), "journal.json")
	journal, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	active := s.client.journal.snapshot().Active
	active.OfferMessageID = "synthetic-secret-offer"
	active.OfferDigest = bytes.Repeat([]byte{1}, sha256.Size)
	active.JobCorrelationV1 = true
	if err := journal.update(func(state *journalState) error { state.Active = active; return nil }); err != nil {
		t.Fatal(err)
	}
	s.client.journal = journal
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.beginSecretRequest(request); err != nil {
		t.Fatal(err)
	}
	delivery, _ := secretExchangeDelivery(s)
	stale := proto.Clone(delivery).(*runnerv1.GatewayMessage)
	if err := s.receiveSecretDelivery(delivery); err != nil {
		t.Fatal(err)
	}
	response := <-request.response
	if response.err != nil || response.files == nil {
		t.Fatal("initial secret delivery failed")
	}
	if err := response.files.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("secret request or response changed the durable journal")
	}
	reopened, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	client := newClient(validConfig(), nil)
	t.Cleanup(func() { _ = client.Close() })
	client.journal = reopened
	client.now = s.client.now
	// A process restart resets both in-memory generation and request counters.
	// Reusing generation 1 is intentional: freshness cannot depend on counters.
	client.sessionGeneration.Store(1)
	next := &clientSession{client: client, generation: 1, reconciled: true, jobCorrelationV1: true, testSecretsV1: true, send: func(*runnerv1.RunnerMessage) error { return nil }}
	fresh := &workerSecretRequest{ctx: context.Background(), generation: 1, response: make(chan secretResponse, 1)}
	if err := next.beginSecretRequest(fresh); err != nil {
		t.Fatal(err)
	}
	if next.pendingSecret == nil || next.pendingSecret.requestID == stale.GetTestSecretsDelivery().RequestMessageId {
		t.Fatal("restart reused a previous connection request identity")
	}
	if err := next.receiveSecretDelivery(stale); err == nil {
		t.Fatal("restarted worker accepted stale connection plaintext")
	}
	if refused := <-fresh.response; refused.err == nil || refused.files != nil || stale.GetTestSecretsDelivery().Secrets[0].Value != nil {
		t.Fatal("stale delivery retained or released plaintext")
	}
	if err := next.beginSecretRequest(fresh); err != nil {
		t.Fatal(err)
	}
	current, _ := secretExchangeDelivery(next)
	if err := next.receiveSecretDelivery(current); err != nil {
		t.Fatal(err)
	}
	response = <-fresh.response
	if response.err != nil || response.files == nil {
		t.Fatal("fresh authorized delivery after restart failed")
	}
	defer response.files.Close()
	after, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("restarted delivery persisted secret-bearing state")
	}
}

func secretExchangeFixture(t *testing.T) (*clientSession, *workerSecretRequest, *[]*runnerv1.RunnerMessage) {
	t.Helper()
	now := time.Now().UTC()
	offer := validLeaseOffer(now)
	job := offer.Job
	job.JobCorrelation = validJobCorrelation(offer)
	addSecretSelection(t, job)
	encoded, err := proto.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	client := newClient(validConfig(), nil)
	t.Cleanup(func() { _ = client.Close() })
	client.now = func() time.Time { return now }
	client.sessionGeneration.Store(1)
	client.journal.state.Active = &journalJob{Specification: encoded, Phase: runnerv1.JobPhase_JOB_PHASE_PREPARING, ExpiresAt: job.Lease.ExpiresAt.AsTime()}
	sent := []*runnerv1.RunnerMessage{}
	session := &clientSession{client: client, generation: 1, reconciled: true, jobCorrelationV1: true, testSecretsV1: true, send: func(m *runnerv1.RunnerMessage) error { sent = append(sent, m); return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	request := &workerSecretRequest{ctx: ctx, generation: 1, response: make(chan secretResponse, 1)}
	return session, request, &sent
}

func secretExchangeDelivery(s *clientSession) (*runnerv1.GatewayMessage, []byte) {
	p := s.pendingSecret
	value := bytes.Repeat([]byte("x"), 65536)
	d := &runnerv1.TestSecretsDelivery{RequestMessageId: p.requestID, Lease: proto.Clone(p.job.Lease).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(p.job.Attempt).(*runnerv1.AttemptIdentity), ExpiresAt: p.job.Lease.ExpiresAt, Secrets: []*runnerv1.TestSecretValue{{Reference: p.job.TestSecrets[0], Value: value}}}
	return &runnerv1.GatewayMessage{MessageId: "secret-delivery", SentAt: timestamppb.New(s.client.now()), Payload: &runnerv1.GatewayMessage_TestSecretsDelivery{TestSecretsDelivery: d}}, value
}

func TestSecretExchangeIsEphemeralAndConsumesExactlyOneDelivery(t *testing.T) {
	s, request, sent := secretExchangeFixture(t)
	before := s.client.journal.snapshot()
	if err := s.beginSecretRequest(request); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 || (*sent)[0].GetTestSecretsRequest() == nil {
		t.Fatal("request not sent")
	}
	message, owned := secretExchangeDelivery(s)
	duplicate := proto.Clone(message).(*runnerv1.GatewayMessage)
	if proto.Size(message) <= MaximumMessageBytes {
		t.Fatal("fixture did not exercise enlarged delivery")
	}
	if err := s.receiveSecretDelivery(message); err != nil {
		t.Fatal(err)
	}
	response := <-request.response
	if response.err != nil || response.files == nil {
		t.Fatal("valid delivery refused")
	}
	defer response.files.Close()
	if !bytes.Equal(owned, make([]byte, len(owned))) || message.GetTestSecretsDelivery().Secrets[0].Value != nil {
		t.Fatal("owned plaintext retained")
	}
	if _, err := response.files.Mounts(); err != nil {
		t.Fatal("sealed files unavailable")
	}
	if s.pendingSecret != nil || len(s.seen) != 0 || len(s.seenOrder) != 0 {
		t.Fatal("delivery retained in session replay state")
	}
	after := s.client.journal.snapshot()
	if !bytes.Equal(before.Active.Specification, after.Active.Specification) || after.MessageSequence != before.MessageSequence || len(after.PendingMessage) != 0 {
		t.Fatal("ephemeral delivery changed durable journal")
	}
	if err := s.receiveSecretDelivery(duplicate); err == nil {
		t.Fatal("duplicate delivery accepted")
	}
	if duplicate.GetTestSecretsDelivery().Secrets[0].Value != nil {
		t.Fatal("duplicate value retained")
	}
}

func TestSecretExchangeRefusesUnacceptedOrWrongSessionRequests(t *testing.T) {
	for _, mode := range []string{"disabled", "uncorrelated", "unreconciled", "wrong-generation", "accepted-only", "cancelled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			s, request, sent := secretExchangeFixture(t)
			switch mode {
			case "disabled":
				s.testSecretsV1 = false
			case "uncorrelated":
				s.jobCorrelationV1 = false
			case "unreconciled":
				s.reconciled = false
			case "wrong-generation":
				request.generation++
			case "accepted-only":
				s.client.journal.state.Active.Phase = runnerv1.JobPhase_JOB_PHASE_ACCEPTED
			case "cancelled":
				s.client.journal.state.Active.CancellationID = "cancelled"
			case "expired":
				s.client.journal.state.Active.ExpiresAt = s.client.now()
			}
			if err := s.beginSecretRequest(request); err != nil {
				t.Fatal(err)
			}
			if response := <-request.response; response.err == nil || response.files != nil {
				t.Fatal("invalid request accepted")
			}
			if len(*sent) != 0 || s.pendingSecret != nil {
				t.Fatal("invalid request reached gateway")
			}
		})
	}
}

func TestSecretExchangeRefusesIdentityDriftAndClearsDelivery(t *testing.T) {
	for _, mode := range []string{"request", "generation", "cancelled", "metadata-drift", "shortened-lease", "expired-delivery"} {
		t.Run(mode, func(t *testing.T) {
			s, request, _ := secretExchangeFixture(t)
			if err := s.beginSecretRequest(request); err != nil {
				t.Fatal(err)
			}
			message, owned := secretExchangeDelivery(s)
			switch mode {
			case "request":
				message.GetTestSecretsDelivery().RequestMessageId = "wrong"
			case "generation":
				s.generation++
			case "cancelled":
				s.client.journal.state.Active.CancellationID = "cancelled"
			case "expired-delivery":
				message.GetTestSecretsDelivery().ExpiresAt = timestamppb.New(s.client.now())
			default:
				job := proto.Clone(s.pendingSecret.job).(*runnerv1.JobSpecification)
				if mode == "metadata-drift" {
					job.TestSecrets[0].Version++
				} else {
					job.Lease.ExpiresAt = timestamppb.New(s.client.now().Add(time.Second))
					s.client.journal.state.Active.ExpiresAt = job.Lease.ExpiresAt.AsTime()
				}
				var err error
				s.client.journal.state.Active.Specification, err = proto.Marshal(job)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := s.receiveSecretDelivery(message); err == nil {
				t.Fatal("invalid delivery accepted")
			}
			if response := <-request.response; response.err == nil || response.files != nil {
				t.Fatal("invalid delivery reached worker")
			}
			if !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatal("refused plaintext retained")
			}
		})
	}
}

func TestSecretWorkerCallbackUsesCurrentLeaseAndSessionAbandonment(t *testing.T) {
	for _, abandon := range []bool{false, true} {
		s, _, sent := secretExchangeFixture(t)
		// Artifact preparation may span a renewal. The callback must use the
		// latest durable lease, not a worker's initial specification copy.
		job := new(runnerv1.JobSpecification)
		if err := proto.Unmarshal(s.client.journal.state.Active.Specification, job); err != nil {
			t.Fatal(err)
		}
		job.Lease.ExpiresAt = timestamppb.New(s.client.now().Add(2 * time.Minute))
		encoded, err := proto.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		s.client.journal.state.Active.Specification = encoded
		s.client.journal.state.Active.ExpiresAt = job.Lease.ExpiresAt.AsTime()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result := make(chan secretResponse, 1)
		go func() {
			files, expiry, err := s.client.requestTestSecretFiles(ctx, 1)
			result <- secretResponse{files: files, expiresAt: expiry, err: err}
		}()
		select {
		case event := <-s.client.workerEvents:
			if err := s.handleWorkerEvent(event); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("worker request not delivered")
		}
		if len(*sent) != 1 || !proto.Equal((*sent)[0].GetTestSecretsRequest().Lease, job.Lease) {
			t.Fatal("request used stale lease")
		}
		if abandon {
			s.abandonSecretRequest()
		} else {
			message, _ := secretExchangeDelivery(s)
			if err := s.receiveSecretDelivery(message); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case response := <-result:
			if abandon {
				if response.err == nil || response.files != nil {
					t.Fatal("abandoned request delivered")
				}
			} else {
				if response.err != nil || response.files == nil || !response.expiresAt.Equal(job.Lease.ExpiresAt.AsTime()) {
					t.Fatal("callback did not receive current sealed delivery")
				}
				_ = response.files.Close()
			}
		case <-ctx.Done():
			t.Fatal("worker response not delivered")
		}
		cancel()
		if s.pendingSecret != nil {
			t.Fatal("pending request not released")
		}
	}
}
