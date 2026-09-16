//go:build linux

package paper

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/measuredclient"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

var errMeasuredWorker = errors.New("measured_worker_session_refused")

// CheckMeasuredService is a fresh authenticated startup idle barrier. It
// reserves no slot; the connected worker still serializes execution admission.
func (provider *Provider) CheckMeasuredService(ctx context.Context, endpoint string) error {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(endpoint) || filepath.Clean(endpoint) != endpoint || len(endpoint) > 107 || strings.ContainsRune(endpoint, 0) {
		return errMeasuredWorker
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	channel, err := dialMeasuredRoot(ctx, endpoint)
	if err != nil {
		return errMeasuredWorker
	}
	if measuredclient.CheckIdle(ctx, channel) != nil {
		return errMeasuredWorker
	}
	return nil
}

// ExecuteMeasured is a separately admitted v2 path. Its caller serializes all
// local work and supplies the operator endpoint, never a path from job JSON.
// It does not fall back to legacy execution when root admission fails.
func (provider *Provider) ExecuteMeasured(ctx context.Context, job *p.JobSpecification, endpoint string, before func(context.Context, execution.ExecutionStart) error) execution.Result {
	fail := func() execution.Result {
		return execution.FailedResult(job.GetLease().GetJobId(), execution.PhasePreparation, execution.ClassificationInfrastructureFailure, "measured_worker_refused", errMeasuredWorker)
	}
	if ctx == nil || ctx.Err() != nil || job == nil || proto.Size(job) > 1<<20 || !filepath.IsAbs(endpoint) || filepath.Clean(endpoint) != endpoint || len(endpoint) > 107 || strings.ContainsRune(endpoint, 0) || len(job.TestSecrets) != 0 {
		return fail()
	}
	job = proto.Clone(job).(*p.JobSpecification)
	proof, err := terminalevidence.NewContextV2(job)
	guard := execution.NetworkAuthorityRoute(ctx)
	if err != nil || guard == nil || guard.CheckJob(job) != nil {
		return fail()
	}
	normalized, _, err := decodeNormalizedConfigurationVersion(job.NormalizedConfigurationJson, true)
	if err != nil || normalized.Resources.LogBytes < 1 || normalized.Resources.LogBytes > 16<<20 {
		return fail()
	}
	collector, err := evidence.NewCollector(evidence.Config{MaxTotalBytes: normalized.Resources.LogBytes, MaxCompleteLogBytes: 16 << 20})
	if err != nil {
		return fail()
	}
	start := execution.ExecutionStart{JobID: job.GetLease().GetJobId(), Provider: ProviderName, EnvironmentIdentity: "measured-paper"}
	session := &measuredWorkerSession{provider: provider, job: job, endpoint: endpoint, collector: collector, maximumLogs: normalized.Resources.LogBytes, before: before, start: start}
	result := execution.ExecuteOwned(ctx, start, session)
	result.TerminalContext = proof
	return result
}

type measuredWorkerSession struct {
	provider           *Provider
	job                *p.JobSpecification
	endpoint           string
	collector          *evidence.Collector
	maximumLogs        int64
	before             func(context.Context, execution.ExecutionStart) error
	start              execution.ExecutionStart
	inputs             *MeasuredInputs
	plan               testPlan
	contacted, retired bool
	accepted           *measuredclient.SessionResult
}

func dialMeasuredRoot(ctx context.Context, endpoint string) (*cc.Channel, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "unixpacket", endpoint)
	if err != nil {
		return nil, errMeasuredWorker
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, errMeasuredWorker
	}
	channel, err := cc.New(unixConn, 0)
	if err != nil {
		conn.Close()
		return nil, errMeasuredWorker
	}
	return channel, nil
}

func (s *measuredWorkerSession) AttachObserver(observer execution.ExecutionObserver) {
	s.collector.SetLiveSink(func(entry evidence.LiveEntry) {
		observer.ObserveLog(execution.LiveLogEntry{Stream: string(entry.Stream), Data: append([]byte(nil), entry.Data...), Partial: entry.Partial, Redacted: entry.Redacted})
	})
}

func (s *measuredWorkerSession) Execute(ctx context.Context) (execution.ExecutionOutcome, error) {
	var err error
	s.inputs, err = s.provider.PrepareMeasuredInputs(ctx, s.job)
	if err != nil {
		return execution.ExecutionOutcome{}, errMeasuredWorker
	}
	if json.Unmarshal(s.inputs.probePlan, &s.plan) != nil {
		return execution.ExecutionOutcome{}, errMeasuredWorker
	}
	channel, err := dialMeasuredRoot(ctx, s.endpoint)
	if err != nil {
		return execution.ExecutionOutcome{}, errMeasuredWorker
	}
	s.contacted = true
	s.accepted, err = measuredclient.Run(ctx, channel, execution.NetworkAuthorityRoute(ctx), measuredclient.SessionOptions{
		Job: s.job, Request: s.inputs.Request(), Files: s.inputs.Files(), PreparationDeadline: s.inputs.PreparationDeadline(), MaximumLogBytes: s.maximumLogs,
		BeforeRelease: func(ctx context.Context) error {
			if s.before != nil {
				return s.before(ctx, s.start)
			}
			return nil
		},
	}, s.collector)
	if err != nil {
		var failure *measuredclient.SessionFailure
		s.retired = errors.As(err, &failure) && failure.RetiredFor(s.job)
		return execution.ExecutionOutcome{}, errMeasuredWorker
	}
	exit, infrastructure, err := s.accepted.Outcome()
	if err != nil {
		return execution.ExecutionOutcome{}, errMeasuredWorker
	}
	s.retired = true
	outcome := execution.ExecutionOutcome{ExitCode: &exit}
	if infrastructure {
		outcome.Failure = execution.NewFailure(execution.ClassificationInfrastructureFailure, "measured_root_execution_failed", "root session reported infrastructure failure")
	} else if exit != 0 {
		outcome.Failure = execution.NewFailure(execution.ClassificationWorkloadFailure, "paper_process_exit_nonzero", "Paper exited unsuccessfully")
	}
	return outcome, nil
}

func (s *measuredWorkerSession) Cleanup(ctx context.Context) error {
	// Run has already closed and joined its local authority writer. Never use
	// the cancelled execution context or renew authority during retirement.
	if s.contacted && !s.retired {
		for ctx.Err() == nil {
			channel, err := dialMeasuredRoot(ctx, s.endpoint)
			if err == nil && measuredclient.CheckIdle(ctx, channel) == nil {
				s.retired = true
				break
			}
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}
	inputErr := s.inputs.Close()
	collectorErr := s.collector.Close()
	if (s.contacted && !s.retired) || inputErr != nil || collectorErr != nil {
		return errMeasuredWorker
	}
	return nil
}

func (s *measuredWorkerSession) Collect(ctx context.Context) (execution.CollectedOutput, error) {
	bundle, err := s.collector.Snapshot(ctx)
	output := execution.CollectedOutput{
		Stdout: bundle.Stdout, Stderr: bundle.Stderr,
		CapturedBytes: bundle.Usage.CapturedBytes, ObservedBytes: bundle.Usage.RawBytesObserved,
		OutputTruncated: bundle.Usage.OutputTruncated, StructuredEventError: bundle.StructuredEventError,
		CompleteLog: &execution.CompleteLog{
			State: bundle.CompleteLog.State, Redacted: bundle.CompleteLog.Redacted, Truncated: bundle.CompleteLog.Truncated, Error: bundle.CompleteLog.Error,
			ContentType: bundle.CompleteLog.ContentType, ContentEncoding: bundle.CompleteLog.ContentEncoding, SHA256: bundle.CompleteLog.SHA256,
			UncompressedBytes: bundle.CompleteLog.UncompressedBytes, CompressedBytes: bundle.CompleteLog.CompressedBytes, Archive: bundle.CompleteLog.Archive,
		},
		EvidenceUsage: execution.EvidenceUsage{
			RawBytesObserved: bundle.Usage.RawBytesObserved, CapturedBytes: bundle.Usage.CapturedBytes,
			StructuredEventCount: bundle.Usage.StructuredEventCount, StructuredEventBytes: bundle.Usage.StructuredEventBytes,
			CompleteLogBytes: bundle.Usage.CompleteLogBytes, CompressedLogBytes: bundle.Usage.CompressedLogBytes,
			TruncatedLineCount: bundle.Usage.TruncatedLineCount, OutputTruncated: bundle.Usage.OutputTruncated,
			CompleteLogState: bundle.Usage.CompleteLogState, CompleteLogTruncated: bundle.Usage.CompleteLogTruncated, EventsTruncated: bundle.Usage.EventsTruncated,
		},
	}
	for _, event := range bundle.Events {
		output.StructuredEvents = append(output.StructuredEvents, execution.StructuredEvent{Sequence: event.Sequence, Kind: event.Kind, Payload: append([]byte(nil), event.Payload...)})
	}
	if s.accepted != nil {
		output.MeasuredNetwork = s.accepted.Observation()
	}
	if err != nil || s.accepted == nil {
		return output, err
	}
	// Reuse the ordinary Paper lifecycle validator and its typed failure-stage
	// mapping. A root exit receipt alone does not establish plugin compatibility.
	delegate := &measuredCollectedOutput{output: output}
	validated := &preparedEnvironment{delegate: delegate, plan: s.plan, terminalEvidenceV2: true}
	_, infrastructure, outcomeErr := s.accepted.Outcome()
	if outcomeErr != nil || infrastructure {
		return output, nil
	}
	return validated.Collect(ctx)
}

type measuredCollectedOutput struct{ output execution.CollectedOutput }

func (m *measuredCollectedOutput) Execute(context.Context) (execution.ExecutionOutcome, error) {
	return execution.ExecutionOutcome{}, errMeasuredWorker
}
func (m *measuredCollectedOutput) Collect(context.Context) (execution.CollectedOutput, error) {
	return m.output, nil
}
func (m *measuredCollectedOutput) Cleanup(context.Context) error { return nil }
