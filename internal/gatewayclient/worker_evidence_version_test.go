package gatewayclient

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type versionRecordingWorker struct{ selected chan bool }

func (w *versionRecordingWorker) Execute(context.Context, *runnerv1.JobSpecification, func(context.Context, execution.ExecutionStart) error) execution.Result {
	w.selected <- false
	return execution.Result{}
}
func (w *versionRecordingWorker) ExecuteV2(context.Context, *runnerv1.JobSpecification, func(context.Context, execution.ExecutionStart) error) execution.Result {
	w.selected <- true
	return execution.Result{}
}

func TestWorkerUsesPersistedEvidenceVersion(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		client, _ := activeEvidenceClient(t, time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC))
		if err := client.journal.update(func(s *journalState) error { s.Active.TerminalEvidenceV2 = v2; return nil }); err != nil {
			t.Fatal(err)
		}
		worker := &versionRecordingWorker{selected: make(chan bool, 1)}
		client.worker = worker
		ctx, cancel := context.WithCancel(context.Background())
		if err := client.startWorker(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		select {
		case selected := <-worker.selected:
			if selected != v2 {
				cancel()
				t.Fatal("worker ignored persisted evidence version")
			}
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("worker did not start")
		}
		cancel()
		client.workerWG.Wait()
	}
}

func TestV2AdvertisementRequiresOptInAndCapableWorker(t *testing.T) {
	client, _ := activeEvidenceClient(t, time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC))
	want := runnerv1.ProtocolFeature_PROTOCOL_FEATURE_TERMINAL_EVIDENCE_V2
	has := func() bool { return advertisedFeature(client.capabilities().Features, want) }
	client.worker = &versionRecordingWorker{selected: make(chan bool, 1)}
	if has() {
		t.Fatal("v2 advertised without rollout opt-in")
	}
	client.config.EnableTerminalEvidenceV2 = true
	if !has() {
		t.Fatal("v2 capable opt-in not advertised")
	}
	if err := validateAdvertisedFeatures(client.capabilities().Features); err != nil {
		t.Fatal(err)
	}
	client.config.DisableTerminalEvidence = true
	if has() {
		t.Fatal("rollback control failed to disable v2")
	}
	client.config.DisableTerminalEvidence = false
	client.worker = nil
	if has() {
		t.Fatal("incapable worker advertised v2")
	}
}

func TestOfferPersistsEvidenceVersionBeforeAcceptance(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
		config := validConfig()
		config.Resources = validOfferConfig().Resources
		client := newClient(config, nil)
		client.worker = &versionRecordingWorker{selected: make(chan bool, 1)}
		authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
		authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
		var sent []*runnerv1.RunnerMessage
		session := &clientSession{client: client, authenticated: authenticated, terminalEvidenceV1: true, terminalEvidenceV2: v2, rootContext: context.Background(), send: func(m *runnerv1.RunnerMessage) error {
			if state := client.journal.snapshot(); state.Active == nil || state.Active.TerminalEvidenceV2 != v2 {
				t.Fatal("acceptance preceded persisted evidence version")
			}
			sent = append(sent, proto.Clone(m).(*runnerv1.RunnerMessage))
			return nil
		}}
		envelope := uniqueGatewayMessage(now, "evidence-version-offer", &runnerv1.GatewayMessage_Offer{Offer: validLeaseOffer(now)})
		if err := session.handleOffer(envelope, now); err != nil {
			t.Fatal(err)
		}
		original := client.journal.snapshot()
		session.terminalEvidenceV2 = !v2
		if err := session.handleOffer(proto.Clone(envelope).(*runnerv1.GatewayMessage), now); err != nil {
			t.Fatal(err)
		}
		current := client.journal.snapshot()
		if len(sent) != 2 || !proto.Equal(sent[0], sent[1]) || current.Active.TerminalEvidenceV2 != v2 || !bytes.Equal(original.Active.Specification, current.Active.Specification) || !bytes.Equal(original.PendingMessage, current.PendingMessage) {
			t.Fatal("re-offer changed accepted version or bytes")
		}
	}
}
