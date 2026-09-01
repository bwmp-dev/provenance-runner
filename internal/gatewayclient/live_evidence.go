package gatewayclient

import (
	"fmt"
	"math"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maximumLiveLogEntryBytes = 16 << 10

type workerEvidenceEvent struct {
	generation uint64
	lease      *runnerv1.LeaseIdentity
	attempt    *runnerv1.AttemptIdentity
	logBatch   *runnerv1.LogBatch
	usage      *runnerv1.UsageReport
}

type liveExecutionObserver struct {
	mu            sync.Mutex
	client        *Client
	lease         *runnerv1.LeaseIdentity
	attempt       *runnerv1.AttemptIdentity
	logSequence   uint64
	usageSequence uint64
	dropped       uint64
	usage         execution.ResourceUsage
}

func newLiveExecutionObserver(client *Client, specification *runnerv1.JobSpecification) *liveExecutionObserver {
	return &liveExecutionObserver{
		client:  client,
		lease:   proto.Clone(specification.GetLease()).(*runnerv1.LeaseIdentity),
		attempt: proto.Clone(specification.GetAttempt()).(*runnerv1.AttemptIdentity),
	}
}

func (observer *liveExecutionObserver) ObserveLog(entry execution.LiveLogEntry) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	stream := runnerv1.LogStream_LOG_STREAM_UNSPECIFIED
	switch entry.Stream {
	case "stdout":
		stream = runnerv1.LogStream_LOG_STREAM_STDOUT
	case "stderr":
		stream = runnerv1.LogStream_LOG_STREAM_STDERR
	default:
		return
	}
	data := entry.Data
	for len(data) > 0 {
		count := liveLogChunkSize(data)
		chunk := append([]byte(nil), data[:count]...)
		data = data[count:]
		if observer.logSequence == math.MaxInt64 {
			observer.dropped = saturatingIncrement(observer.dropped)
			continue
		}
		observer.logSequence++
		logEntry := &runnerv1.LogEntry{
			Sequence:   observer.logSequence,
			ObservedAt: timestamppb.New(observer.client.now().UTC()),
			Stream:     stream,
			Data:       chunk,
			Partial:    len(data) > 0 || entry.Partial,
			Redacted:   entry.Redacted,
		}
		batch := &runnerv1.LogBatch{Lease: proto.Clone(observer.lease).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(observer.attempt).(*runnerv1.AttemptIdentity), Entries: []*runnerv1.LogEntry{logEntry}, DroppedEntryCount: observer.dropped}
		event := workerEvent{evidence: &workerEvidenceEvent{generation: observer.client.sessionGeneration.Load(), lease: batch.Lease, attempt: batch.Attempt, logBatch: batch}}
		select {
		case observer.client.workerEvents <- event:
			observer.dropped = 0
		default:
			observer.dropped = saturatingIncrement(observer.dropped)
		}
	}
}

func (observer *liveExecutionObserver) finalDroppedEvent() *workerEvidenceEvent {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if observer.dropped == 0 {
		return nil
	}
	batch := &runnerv1.LogBatch{Lease: proto.Clone(observer.lease).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(observer.attempt).(*runnerv1.AttemptIdentity), DroppedEntryCount: observer.dropped}
	observer.dropped = 0
	return &workerEvidenceEvent{generation: observer.client.sessionGeneration.Load(), lease: batch.Lease, attempt: batch.Attempt, logBatch: batch}
}

func liveLogChunkSize(data []byte) int {
	count := min(len(data), maximumLiveLogEntryBytes)
	if count == len(data) || utf8.Valid(data[:count]) {
		return count
	}
	for count > 0 && !utf8.Valid(data[:count]) {
		count--
	}
	if count == 0 {
		return min(len(data), maximumLiveLogEntryBytes)
	}
	return count
}

func (observer *liveExecutionObserver) ObserveUsage(measured execution.ResourceUsage) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	mergeResourceUsage(&observer.usage, measured)
	event := observer.nextUsageEventLocked()
	if event == nil {
		return
	}
	select {
	case observer.client.workerEvents <- workerEvent{evidence: event}:
	default:
		// Usage reports are intentionally non-journaled. The final cumulative
		// value remains attached to the durable terminal result.
	}
}

func (observer *liveExecutionObserver) finalUsageEvent(measured execution.ResourceUsage) *workerEvidenceEvent {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	mergeResourceUsage(&observer.usage, measured)
	return observer.nextUsageEventLocked()
}

func (observer *liveExecutionObserver) nextUsageEventLocked() *workerEvidenceEvent {
	if observer.usageSequence == math.MaxInt64 {
		return nil
	}
	observer.usageSequence++
	observedAt := observer.client.now().UTC().Truncate(time.Microsecond)
	report := &runnerv1.UsageReport{
		Lease:      proto.Clone(observer.lease).(*runnerv1.LeaseIdentity),
		Attempt:    proto.Clone(observer.attempt).(*runnerv1.AttemptIdentity),
		Sequence:   observer.usageSequence,
		ObservedAt: timestamppb.New(observedAt),
		Cumulative: resourceUsageMessage(observer.usage),
	}
	return &workerEvidenceEvent{generation: observer.client.sessionGeneration.Load(), lease: report.Lease, attempt: report.Attempt, usage: report}
}

func (s *clientSession) sendWorkerEvidence(event *workerEvidenceEvent) error {
	if event == nil || event.generation != s.generation {
		return nil
	}
	state := s.client.journal.snapshot()
	if state.Active == nil || state.Active.CancellationID != "" || !state.Active.ExpiresAt.After(s.client.now().UTC()) || !activeMatchesIdentity(state.Active, event.lease, event.attempt) {
		return nil
	}
	message := &runnerv1.RunnerMessage{SentAt: timestamppb.New(s.client.now().UTC())}
	sequence := s.client.ephemeralSequence.Add(1)
	if sequence == 0 || sequence > math.MaxInt64 {
		return nil
	}
	message.MessageId = fmt.Sprintf("live-%016x", sequence)
	if event.logBatch != nil {
		message.Payload = &runnerv1.RunnerMessage_LogBatch{LogBatch: event.logBatch}
	} else if event.usage != nil {
		message.Payload = &runnerv1.RunnerMessage_Usage{Usage: event.usage}
	} else {
		return nil
	}
	if proto.Size(message) > MaximumMessageBytes {
		return nil
	}
	return s.send(message)
}

func resourceUsageMessage(usage execution.ResourceUsage) *runnerv1.ResourceUsage {
	message := &runnerv1.ResourceUsage{
		PeakMemoryBytes:      usage.PeakMemoryBytes,
		DiskReadBytes:        usage.DiskReadBytes,
		DiskWriteBytes:       usage.DiskWriteBytes,
		NetworkReceiveBytes:  usage.NetworkReceiveBytes,
		NetworkTransmitBytes: usage.NetworkTransmitBytes,
	}
	if usage.CPUTime > 0 {
		message.CpuTime = durationpb.New(usage.CPUTime)
	}
	return message
}

func mergeResourceUsage(current *execution.ResourceUsage, measured execution.ResourceUsage) {
	if measured.CPUTime > current.CPUTime {
		current.CPUTime = measured.CPUTime
	}
	if measured.PeakMemoryBytes > current.PeakMemoryBytes {
		current.PeakMemoryBytes = measured.PeakMemoryBytes
	}
	if measured.DiskReadBytes > current.DiskReadBytes {
		current.DiskReadBytes = measured.DiskReadBytes
	}
	if measured.DiskWriteBytes > current.DiskWriteBytes {
		current.DiskWriteBytes = measured.DiskWriteBytes
	}
	if measured.NetworkReceiveBytes > current.NetworkReceiveBytes {
		current.NetworkReceiveBytes = measured.NetworkReceiveBytes
	}
	if measured.NetworkTransmitBytes > current.NetworkTransmitBytes {
		current.NetworkTransmitBytes = measured.NetworkTransmitBytes
	}
}

func saturatingIncrement(value uint64) uint64 {
	if value == math.MaxUint64 {
		return value
	}
	return value + 1
}
