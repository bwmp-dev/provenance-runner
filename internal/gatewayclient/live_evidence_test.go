package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func TestLiveObserverBoundsSequencesDropsAndDoesNotBlock(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 123456789, time.UTC)
	client, offer := activeEvidenceClient(t, now)
	observer := newLiveExecutionObserver(client, offer.GetJob())
	data := bytes.Repeat([]byte("界"), maximumLiveLogEntryBytes)
	observer.ObserveLog(execution.LiveLogEntry{Stream: "stdout", Data: data, Redacted: true})
	var batches []*runnerv1.LogBatch
	for len(client.workerEvents) > 0 {
		event := <-client.workerEvents
		batches = append(batches, event.evidence.logBatch)
	}
	if len(batches) < 2 {
		t.Fatalf("batches = %d", len(batches))
	}
	var previous uint64
	for index, batch := range batches {
		entry := batch.GetEntries()[0]
		if len(entry.GetData()) > maximumLiveLogEntryBytes || !utf8.Valid(entry.GetData()) || entry.GetSequence() <= previous || !entry.GetRedacted() {
			t.Fatalf("batch %d = %#v", index, batch)
		}
		previous = entry.GetSequence()
		if index < len(batches)-1 && !entry.GetPartial() {
			t.Fatalf("chunk %d is not partial", index)
		}
	}

	for len(client.workerEvents) < cap(client.workerEvents) {
		client.workerEvents <- workerEvent{start: make(chan error, 1)}
	}
	observer.ObserveLog(execution.LiveLogEntry{Stream: "stderr", Data: []byte("dropped\n")})
	for len(client.workerEvents) > 0 {
		<-client.workerEvents
	}
	observer.ObserveLog(execution.LiveLogEntry{Stream: "stderr", Data: []byte("visible\n")})
	event := <-client.workerEvents
	if event.evidence.logBatch.GetDroppedEntryCount() != 1 {
		t.Fatalf("dropped count = %d", event.evidence.logBatch.GetDroppedEntryCount())
	}
}

func TestUsageReportsAreMonotonicNonDurableAndMatchTerminal(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 123456789, time.UTC)
	client, offer := activeEvidenceClient(t, now)
	client.clearCompleteLogTarget()
	client.sessionGeneration.Store(7)
	observer := newLiveExecutionObserver(client, offer.GetJob())
	observer.ObserveUsage(execution.ResourceUsage{CPUTime: 3 * time.Second, PeakMemoryBytes: 9, DiskReadBytes: 7})
	observer.ObserveUsage(execution.ResourceUsage{CPUTime: time.Second, PeakMemoryBytes: 4, DiskWriteBytes: 5})
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{client: client, generation: 7, rootContext: context.Background(), send: func(message *runnerv1.RunnerMessage) error {
		sent = append(sent, message)
		return nil
	}}
	for len(client.workerEvents) > 0 {
		if err := session.handleWorkerEvent(<-client.workerEvents); err != nil {
			t.Fatal(err)
		}
	}
	if len(sent) != 2 || sent[0].GetUsage().GetSequence() != 1 || sent[1].GetUsage().GetSequence() != 2 {
		t.Fatalf("usage messages = %#v", sent)
	}
	latest := sent[1].GetUsage()
	if latest.GetCumulative().GetCpuTime().AsDuration() != 3*time.Second || latest.GetCumulative().GetPeakMemoryBytes() != 9 || latest.GetCumulative().GetDiskReadBytes() != 7 || latest.GetCumulative().GetDiskWriteBytes() != 5 || latest.GetObservedAt().GetNanos()%int32(time.Microsecond) != 0 {
		t.Fatalf("latest usage = %#v", latest)
	}
	if len(client.journal.snapshot().PendingMessage) != 0 {
		t.Fatal("usage report was journaled")
	}
	resultUsage := execution.ResourceUsage{CPUTime: 3 * time.Second, PeakMemoryBytes: 9, DiskReadBytes: 7, DiskWriteBytes: 5}
	result := execution.Result{SchemaVersion: execution.ResultSchemaVersion, JobID: offer.GetJob().GetLease().GetJobId(), Status: "passed", Classification: execution.ClassificationPassed, Phase: execution.PhaseCompleted, StartedAt: now, CompletedAt: now, Usage: execution.UsageResult{MeasuredResources: &resultUsage}}
	if err := session.handleWorkerEvent(workerEvent{result: &result, finalUsage: observer.finalUsageEvent(resultUsage)}); err != nil {
		t.Fatal(err)
	}
	finalReport := sent[len(sent)-2].GetUsage()
	terminal := sent[len(sent)-1].GetCompleted().GetResult().GetUsage()
	if finalReport.GetSequence() != 3 || terminal.GetCpuTime().AsDuration() != finalReport.GetCumulative().GetCpuTime().AsDuration() || terminal.GetPeakMemoryBytes() != finalReport.GetCumulative().GetPeakMemoryBytes() || terminal.GetDiskWriteBytes() != finalReport.GetCumulative().GetDiskWriteBytes() {
		t.Fatalf("terminal usage = %#v final report = %#v", terminal, finalReport)
	}
	if len(client.journal.snapshot().PendingMessage) == 0 {
		t.Fatal("terminal result was not durable")
	}
}

func TestLiveEvidencePayloadsAreNeverClassifiedAsJournalDurable(t *testing.T) {
	if durableRunnerMessage(&runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_LogBatch{LogBatch: &runnerv1.LogBatch{}}}) {
		t.Fatal("LogBatch is journal durable")
	}
	if durableRunnerMessage(&runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_Usage{Usage: &runnerv1.UsageReport{}}}) {
		t.Fatal("UsageReport is journal durable")
	}
}

func TestStaleSessionEvidenceIsDiscarded(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	client, offer := activeEvidenceClient(t, now)
	client.sessionGeneration.Store(1)
	observer := newLiveExecutionObserver(client, offer.GetJob())
	observer.ObserveLog(execution.LiveLogEntry{Stream: "stdout", Data: []byte("old\n")})
	event := <-client.workerEvents
	called := false
	session := &clientSession{client: client, generation: 2, send: func(*runnerv1.RunnerMessage) error { called = true; return nil }}
	if err := session.handleWorkerEvent(event); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("stale session evidence was sent")
	}
}

func TestCancellationSendsOnlyOneIdentitySafeFinalUsageBeforeTerminal(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 123456789, time.UTC)
	client, offer := activeEvidenceClient(t, now)
	client.clearCompleteLogTarget()
	client.sessionGeneration.Store(7)
	if err := client.journal.update(func(state *journalState) error {
		state.Active.CancellationID = "cancellation-1"
		state.Active.CancellationDigest = bytes.Repeat([]byte{1}, sha256.Size)
		state.Active.CancellationDeadline = now.Add(time.Minute)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	observer := newLiveExecutionObserver(client, offer.GetJob())
	usage := execution.ResourceUsage{CPUTime: 2 * time.Second, PeakMemoryBytes: 32, DiskReadBytes: 11, DiskWriteBytes: 13}
	final := observer.finalUsageEvent(usage)
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{client: client, generation: 7, rootContext: context.Background(), send: func(message *runnerv1.RunnerMessage) error {
		sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
		return nil
	}}

	periodic := *final
	periodic.terminal = false
	if err := session.sendWorkerEvidence(&periodic); err != nil {
		t.Fatal(err)
	}
	staleGeneration := *final
	staleGeneration.generation = 6
	if err := session.sendWorkerEvidence(&staleGeneration); err != nil {
		t.Fatal(err)
	}
	staleIdentity := *final
	staleIdentity.lease = proto.Clone(final.lease).(*runnerv1.LeaseIdentity)
	staleIdentity.lease.LeaseId = "00000000-0000-4000-8000-000000000099"
	if err := session.sendWorkerEvidence(&staleIdentity); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 0 {
		t.Fatalf("non-final or stale cancellation evidence was sent: %#v", sent)
	}

	result := execution.Result{
		SchemaVersion:  execution.ResultSchemaVersion,
		JobID:          offer.GetJob().GetLease().GetJobId(),
		Status:         "failed",
		Classification: execution.ClassificationCancelled,
		Phase:          execution.PhaseCleanup,
		StartedAt:      now,
		CompletedAt:    now.Add(time.Second),
		Cleanup:        &execution.CleanupResult{Attempted: true, Succeeded: true},
		Usage:          execution.UsageResult{MeasuredResources: &usage},
	}
	if err := session.handleWorkerEvent(workerEvent{result: &result, finalUsage: final}); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[0].GetUsage() == nil || sent[1].GetCancelled() == nil {
		t.Fatalf("cancellation ordering = %#v", sent)
	}
	if cumulative := sent[0].GetUsage().GetCumulative(); cumulative.GetDiskReadBytes() != 11 || cumulative.GetDiskWriteBytes() != 13 {
		t.Fatalf("final cancellation usage = %#v", cumulative)
	}
	if err := session.sendWorkerEvidence(final); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 {
		t.Fatalf("duplicate final cancellation usage was sent: %#v", sent)
	}

	reconnected := &clientSession{client: client, generation: 8, send: func(message *runnerv1.RunnerMessage) error {
		sent = append(sent, message)
		return nil
	}}
	if err := reconnected.sendWorkerEvidence(final); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 {
		t.Fatal("final cancellation usage was replayed after reconnect")
	}
}

func TestCancellationFinalUsageIsNotRetriedAfterAmbiguousSendFailure(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	client, offer := activeEvidenceClient(t, now)
	client.sessionGeneration.Store(4)
	if err := client.journal.update(func(state *journalState) error {
		state.Active.CancellationID = "cancellation-1"
		state.Active.CancellationDigest = bytes.Repeat([]byte{1}, sha256.Size)
		state.Active.CancellationDeadline = now.Add(time.Minute)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	event := newLiveExecutionObserver(client, offer.GetJob()).finalUsageEvent(execution.ResourceUsage{CPUTime: time.Second})
	attempts := 0
	session := &clientSession{client: client, generation: 4, send: func(*runnerv1.RunnerMessage) error {
		attempts++
		return errors.New("ambiguous stream failure")
	}}
	if err := session.sendWorkerEvidence(event); err == nil {
		t.Fatal("initial send failure = nil")
	}
	if err := session.sendWorkerEvidence(event); err != nil {
		t.Fatalf("suppressed retry error = %v", err)
	}
	if attempts != 1 {
		t.Fatalf("send attempts = %d, want 1", attempts)
	}
}
