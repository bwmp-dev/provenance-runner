package gatewayclient

import (
	"bytes"
	"context"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
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
