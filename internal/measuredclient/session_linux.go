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
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
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
	// PrepareSecrets runs only after root observation, before Java release.
	// The caller owns returned descriptors through Run and configures redaction
	// before returning. Values never enter job JSON or startup metadata.
	PrepareSecrets func(context.Context, *runtimeidentity.NetworkObservation) ([]ts.Descriptor, time.Time, error)
	// PrepareOutput replaces the caller-owned collector before any guest output
	// is consumed. This supports redaction configured by late secret delivery.
	PrepareOutput func(context.Context) (*evidence.Collector, error)
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
	// Secret acquisition belongs to PREPARING. The gateway start callback
	// commits RUNNING, after which its secret source deliberately refuses reads.
	// Root observation and current authority are already required above; Java's
	// bootstrap gate remains closed throughout this preparation.
	var secretExpiry time.Time
	if len(job.TestSecrets) > 0 {
		if options.PrepareSecrets == nil || ts.ValidateSelection(job) != nil || guard.CheckJob(job) != nil {
			return nil, ErrSession
		}
		descriptors, expires, err := options.PrepareSecrets(preparationCtx, observation)
		ceiling, authorityErr := guard.CurrentLeaseExpiry(job)
		if err != nil || authorityErr != nil || !expires.After(time.Now()) || expires.After(ceiling) || len(descriptors) != len(job.TestSecrets) {
			return nil, ErrSession
		}
		names, files := make([]string, len(descriptors)), make([]*os.File, len(descriptors))
		for i, descriptor := range descriptors {
			if descriptor.Name != job.TestSecrets[i].Name {
				return nil, ErrSession
			}
			names[i], files[i] = descriptor.Name, descriptor.File
		}
		if forwarder.DeliverSecrets(preparationCtx, names, files, expires) != nil {
			return nil, ErrSession
		}
		secretExpiry = expires
	} else if options.PrepareSecrets != nil {
		return nil, ErrSession
	}
	if options.PrepareOutput != nil {
		collector, err = options.PrepareOutput(preparationCtx)
		if err != nil || collector == nil {
			return nil, ErrSession
		}
	}
	ready := func() bool {
		return preparationCtx.Err() == nil && (secretExpiry.IsZero() || secretExpiry.After(time.Now())) && guard.CheckJob(job) == nil
	}
	// An acknowledgement wait cannot extend the delivery expiry or restore
	// withdrawn authority. Root independently rechecks both at bootstrap.
	if acknowledgePreparedRelease(preparationCtx, options.BeforeRelease, ready) != nil {
		return nil, ErrSession
	}
	executionCtx, stopExecution := context.WithTimeout(ctx, execution)
	defer stopExecution()
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

func acknowledgePreparedRelease(ctx context.Context, before func(context.Context) error, ready func() bool) error {
	if ctx == nil || ctx.Err() != nil || ready == nil || !ready() {
		return ErrSession
	}
	if before != nil && before(ctx) != nil {
		return ErrSession
	}
	if ctx.Err() != nil || !ready() {
		return ErrSession
	}
	return nil
}
