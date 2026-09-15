//go:build linux

package measuredclient

import (
	"context"
	"os"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

// SessionOptions are supplied by the trusted provider, not job JSON. Files are
// borrowed through SendStart; PreparationDeadline starts before downloading.
type SessionOptions struct {
	Job                 *p.JobSpecification
	Request             []byte
	Files               []*os.File
	PreparationDeadline time.Time
	MaximumLogBytes     int64
	BeforeRelease       func(context.Context) error
}

// SessionResult exists only after the same authenticated root session supplied
// an exact-job observation and retired completion. It does not validate Paper
// lifecycle events or classify plugin compatibility.
type SessionResult struct {
	observation *runtimeidentity.NetworkObservation
	completion  *cc.RootCompletion
}

func (r *SessionResult) Observation() *runtimeidentity.NetworkObservation {
	if r == nil {
		return nil
	}
	return r.observation
}

func (r *SessionResult) Outcome() (int, bool, error) {
	if r == nil || r.completion == nil {
		return 0, false, ErrSession
	}
	return r.completion.Outcome()
}

// Run owns the channel on every path. It never returns a partial result as a
// completion; the collector remains caller-owned and may retain redacted
// diagnostics on failure. Callers must separately validate provider events.
func Run(ctx context.Context, channel *cc.Channel, guard *np.AuthorityRoute, options SessionOptions, collector *evidence.Collector) (*SessionResult, error) {
	if channel == nil {
		return nil, ErrSession
	}
	defer channel.Close()
	// Authenticate root before any private artifact descriptor is transferred.
	peer, peerErr := channel.PeerUID()
	if peerErr != nil || peer != 0 {
		return nil, ErrSession
	}
	if ctx == nil || ctx.Err() != nil || guard == nil || collector == nil || options.Job == nil || proto.Size(options.Job) > 1<<20 || options.MaximumLogBytes <= 0 || options.MaximumLogBytes > 16<<20 {
		return nil, ErrSession
	}
	job := proto.Clone(options.Job).(*p.JobSpecification)
	policy := job.EffectivePolicy
	if policy == nil || policy.PreparationTimeout == nil || policy.ExecutionTimeout == nil || policy.PreparationTimeout.CheckValid() != nil || policy.ExecutionTimeout.CheckValid() != nil {
		return nil, ErrSession
	}
	preparation, execution := policy.PreparationTimeout.AsDuration(), policy.ExecutionTimeout.AsDuration()
	if preparation < time.Millisecond || preparation > time.Hour || execution < time.Millisecond || execution > time.Hour || !options.PreparationDeadline.After(time.Now()) || time.Until(options.PreparationDeadline) > preparation || guard.CheckJob(job) != nil {
		return nil, ErrSession
	}
	ctx, cancel := context.WithDeadline(ctx, options.PreparationDeadline.Add(execution+15*time.Second))
	defer cancel()
	stop := context.AfterFunc(ctx, func() { channel.Close() })
	defer stop()
	preparationCtx, stopPreparation := context.WithDeadline(ctx, options.PreparationDeadline)
	defer stopPreparation()
	deadline := time.Now().Add(10 * time.Second)
	if options.PreparationDeadline.Before(deadline) {
		deadline = options.PreparationDeadline
	}
	last, err := cc.SendStart(channel, options.Request, options.Files, deadline)
	if err != nil {
		return nil, ErrSession
	}
	forwarder, err := StartAuthorityForwarder(ctx, channel, guard, job, last)
	if err != nil {
		return nil, ErrSession
	}
	defer forwarder.Close()
	packet, err := channel.AwaitRootObservation(preparationCtx)
	if err != nil {
		return nil, ErrSession
	}
	observation, err := runtimeidentity.ImportRootObservation(job, packet)
	if err != nil || preparationCtx.Err() != nil {
		return nil, ErrSession
	}
	executionCtx, stopExecution := context.WithTimeout(ctx, execution)
	defer stopExecution()
	if options.BeforeRelease != nil && options.BeforeRelease(executionCtx) != nil {
		return nil, ErrSession
	}
	if executionCtx.Err() != nil || forwarder.Release(executionCtx) != nil {
		return nil, ErrSession
	}
	// Root enforces the execution budget on the actual process. Allow a fixed
	// additional retirement interval before requiring its completion receipt.
	resultCtx, stopResult := context.WithTimeout(ctx, execution+15*time.Second)
	defer stopResult()
	stopResultSocket := context.AfterFunc(resultCtx, func() { channel.Close() })
	defer stopResultSocket()
	stream, err := cc.NewResultStream(resultCtx, channel)
	if err != nil {
		return nil, ErrSession
	}
	defer stream.Close()
	transcript, err := collector.ConsumeGuest(resultCtx, stream, options.MaximumLogBytes)
	if err != nil || transcript == nil {
		// Event validation can fail after the authenticated stream has already
		// reached root completion. Preserve only that historical cleanup fact,
		// never turn a refused transcript into a successful session result.
		if receipt, receiptErr := stream.Receipt(); receiptErr == nil {
			return nil, &SessionFailure{observation: observation, completion: receipt}
		}
		return nil, ErrSession
	}
	completion, err := stream.Receipt()
	if err != nil {
		return nil, ErrSession
	}
	exit, infrastructure, err := completion.Outcome()
	claimedExit, claimedInfrastructure := transcript.ClaimedExit()
	if err != nil || exit != claimedExit || (claimedInfrastructure && !infrastructure) || resultCtx.Err() != nil {
		return nil, &SessionFailure{observation: observation, completion: completion}
	}
	return &SessionResult{observation: observation, completion: completion}, nil
}
