//go:build linux

// Package measuredservice composes authenticated local requests with the root
// controller. It never loads gateway credentials or downloads caller URLs.
package measuredservice

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	"github.com/bwmp-dev/provenance-runner/internal/guestoutput"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/provider/gvisor"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	"google.golang.org/protobuf/proto"
)

var ErrService = errors.New("measured_paper_service_refused")

// Config is trusted root provisioning, never a wire schema. Controller
// ownership transfers on successful New; journal ownership remains with its
// provisioner until Server.Close succeeds.
type Config struct {
	Controller        *gvisor.MeasuredController
	Measurement       *runtimeidentity.Lease
	RuntimeSource     *paper.RuntimeSource
	WorkerUID         uint32
	MaximumInputBytes uint64
	EnableSecrets     bool
}

type Server struct {
	mu             sync.Mutex
	ctx            context.Context
	stop           context.CancelFunc
	controller     *gvisor.MeasuredController
	measurement    *runtimeidentity.Lease
	source         *paper.RuntimeSource
	worker         uint32
	maximum        uint64
	failed, closed bool
	secrets        bool
	// In-package disposable fixtures may observe retirement failures. This is
	// unset in every constructor and cannot be enabled by configuration or wire
	// input. It never receives guest bytes, input descriptors or secret values.
	fixtureCompletion func(int, bool, error, error, error, error)
}

func New(ctx context.Context, config Config) (*Server, error) {
	groups, err := os.Getgroups()
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || err != nil || len(groups) != 0 || config.Controller == nil || config.Measurement == nil || config.RuntimeSource == nil || len(config.RuntimeSource.PublicKey) != ed25519.PublicKeySize || config.WorkerUID == 0 || config.WorkerUID == ^uint32(0) || config.MaximumInputBytes == 0 || config.MaximumInputBytes > 64<<30 {
		return nil, ErrService
	}
	if config.EnableSecrets && !config.Controller.SupportsTestSecretStorage() {
		return nil, ErrService
	}
	source, err := paper.NewRuntimeSource(config.RuntimeSource.Origin, hex.EncodeToString(config.RuntimeSource.PublicKey))
	if err != nil {
		return nil, ErrService
	}
	source.Client = nil
	measurement, err := config.Measurement.Retain()
	if err != nil {
		return nil, ErrService
	}
	if measurement.ValidatePaperGuestTarget() != nil || (config.EnableSecrets && measurement.ValidateTestSecretTarget() != nil) {
		measurement.Close()
		return nil, ErrService
	}
	root, stop := context.WithCancel(ctx)
	return &Server{ctx: root, stop: stop, controller: config.Controller, measurement: measurement, source: source, worker: config.WorkerUID, maximum: config.MaximumInputBytes, secrets: config.EnableSecrets}, nil
}

// Close first cancels admission/execution. Failed controller cleanup retains all
// owners for retry; callers must not close journals or reuse their provisioning.
func (s *Server) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil || s.stop == nil {
		return ErrService
	}
	s.stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := s.controller.Close(ctx); err != nil {
		s.failed = true
		return errors.Join(ErrService, err)
	}
	if err := s.measurement.Close(); err != nil {
		s.failed = true
		return errors.Join(ErrService, err)
	}
	s.closed = true
	return nil
}

// Serve owns the channel on every path. Admission is non-blocking and globally
// serialized before reading any request bytes or allocating transferred FDs.
func (s *Server) Serve(ctx context.Context, channel *cc.Channel) (result error) {
	if channel == nil {
		return ErrService
	}
	defer channel.Close()
	if s == nil || ctx == nil || s.ctx == nil || !s.mu.TryLock() {
		return ErrService
	}
	defer s.mu.Unlock()
	peer, err := channel.PeerUID()
	if err != nil || peer != s.worker || s.closed || s.failed || s.ctx.Err() != nil || ctx.Err() != nil {
		return ErrService
	}
	jobCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)
	stopServer := context.AfterFunc(s.ctx, func() { cancel(ErrService) })
	defer stopServer()
	stopSocket := context.AfterFunc(ctx, func() { channel.Close() })
	defer stopSocket()
	stopServiceSocket := context.AfterFunc(s.ctx, func() { channel.Close() })
	defer stopServiceSocket()
	request, err := cc.ReceiveServiceRequest(channel, time.Now().Add(10*time.Second))
	if err != nil {
		return ErrService
	}
	defer func() {
		for _, file := range request.Files {
			_ = file.Close()
		}
	}()
	if len(request.IdleNonce) != 0 || len(request.SecretNonce) != 0 || len(request.MaximumNonce) != 0 {
		// Serve holds admission throughout this probe. A previous Serve must
		// finish its deferred controller cleanup before this lock is available.
		if s.controller.CheckIdle() != nil || s.measurement.ValidatePaperGuestTarget() != nil {
			return ErrService
		}
		kind, nonce := cc.IdleConfirmed, request.IdleNonce
		if len(request.MaximumNonce) != 0 {
			maximum, err := s.controller.LocalMaximum()
			if err != nil {
				return ErrService
			}
			raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(maximum)
			if err != nil || len(raw) == 0 || len(raw) > 16<<10 {
				return ErrService
			}
			return channel.Send(cc.Packet{Kind: cc.MaximumConfirmed, Sequence: 1, Payload: append(request.MaximumNonce, raw...)}, time.Now().Add(5*time.Second))
		}
		if len(request.SecretNonce) != 0 {
			if !s.secrets || !s.controller.SupportsTestSecretStorage() || s.measurement.ValidateTestSecretTarget() != nil {
				return ErrService
			}
			kind, nonce = cc.SecretConfirmed, request.SecretNonce
		}
		return channel.Send(cc.Packet{Kind: kind, Sequence: 1, Payload: nonce}, time.Now().Add(5*time.Second))
	}
	send := &sender{channel: channel}
	stopKeep, keepDone := keepalive(jobCtx, send, cancel)
	defer func() { stopKeep(); <-keepDone }()
	prepare := s.source.PrepareMeasuredRequest
	if s.secrets {
		prepare = s.source.PrepareMeasuredRequestWithSecrets
	}
	plan, err := prepare(request.Payload, s.maximum)
	if err != nil || s.measurement.ValidatePaperGuestTarget() != nil {
		return ErrService
	}
	roles := plan.Inputs()
	if len(roles) != len(request.Files) {
		return ErrService
	}
	job := plan.Job()
	deadline := time.Now().Add(job.EffectivePolicy.PreparationTimeout.AsDuration() + job.EffectivePolicy.ExecutionTimeout.AsDuration() + 10*time.Second)
	bounded, stopBudget := context.WithDeadline(jobCtx, deadline)
	defer stopBudget()
	jobCtx = bounded
	inputs := make([]gvisor.MeasuredInput, len(roles))
	for i, role := range roles {
		inputs[i] = gvisor.MeasuredInput{Name: role.Name, Source: request.Files[i], Size: role.SizeBytes, SHA256: role.SHA256}
	}
	authority, err := np.NewAuthorityRoute(jobCtx, job)
	if err != nil {
		return ErrService
	}
	var owned *gvisor.MeasuredControllerJob
	defer func() {
		var err error
		if owned != nil {
			err = owned.Close(context.Background())
		} else {
			err = authority.Close()
		}
		if err != nil {
			s.failed = true
			result = errors.Join(ErrService, result, err)
		}
	}()
	if receiveAuthority(jobCtx, channel, authority) != nil {
		return ErrService
	}
	controlDone := make(chan struct{})
	released := make(chan struct{})
	var releaseAllowed, releaseUsed atomic.Bool
	var secretUsed, secretReady bool
	var secretExpiry time.Time
	secretRequired := len(job.TestSecrets) > 0
	go func() {
		defer close(controlDone)
		for i := 0; i < 8192; i++ {
			packet, err := receiveServicePacket(jobCtx, channel)
			if err != nil {
				cancel(err)
				return
			}
			if packet.Kind == cc.Release {
				if len(packet.Payload) != 0 || !releaseAllowed.Load() || (secretRequired && (!secretReady || !secretExpiry.After(time.Now()))) || !releaseUsed.CompareAndSwap(false, true) {
					cancel(ErrService)
					return
				}
				close(released)
				continue
			}
			if packet.Kind == cc.SecretDelivery {
				if !s.secrets || !secretRequired || !releaseAllowed.Load() || releaseUsed.Load() || secretUsed {
					cancel(ErrService)
					return
				}
				secretUsed = true
				ceiling, err := authority.CurrentLeaseExpiry(job)
				if err != nil {
					cancel(ErrService)
					return
				}
				names := make([]string, len(job.TestSecrets))
				for i, ref := range job.TestSecrets {
					names[i] = ref.Name
				}
				until := time.Now().Add(5 * time.Second)
				if end, ok := jobCtx.Deadline(); ok && end.Before(until) {
					until = end
				}
				delivery, err := cc.ReceiveSecrets(channel, packet, names, ceiling, until)
				if err != nil {
					cancel(ErrService)
					return
				}
				descriptors := make([]ts.Descriptor, len(delivery.Files))
				for i, file := range delivery.Files {
					descriptors[i] = ts.Descriptor{Name: delivery.Names[i], File: file}
				}
				err = owned.MaterializeTestSecrets(jobCtx, descriptors, delivery.ExpiresAt)
				closeErr := delivery.Close()
				if err != nil || closeErr != nil {
					cancel(ErrService)
					return
				}
				secretExpiry = delivery.ExpiresAt
				secretReady = true
				continue
			}
			if err := applyAuthorityPacket(jobCtx, packet, authority); err != nil {
				cancel(err)
				return
			}
		}
		cancel(ErrService)
	}()
	defer func() { channel.Close(); <-controlDone }()
	var pipes []*os.File
	defer func() {
		for _, file := range pipes {
			_ = file.Close()
		}
	}()
	pipe := func() (*os.File, *os.File, error) {
		r, w, e := os.Pipe()
		if e == nil {
			pipes = append(pipes, r, w)
		}
		return r, w, e
	}
	inR, inW, err := pipe()
	if err != nil {
		return ErrService
	}
	outR, outW, err := pipe()
	if err != nil {
		return ErrService
	}
	errR, errW, err := pipe()
	if err != nil {
		return ErrService
	}
	pipeDone := make(chan struct{})
	defer close(pipeDone)
	stopPipes := context.AfterFunc(jobCtx, func() {
		inW.Close()
		// The controller kills the owned process tree on cancellation. Allow
		// its pipes to reach real EOF so a late acknowledgement during normal
		// retirement cannot truncate already completed guest output. If drain
		// fails, interrupt IO after a fixed grace and retain failed ownership.
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-pipeDone:
		case <-timer.C:
			outR.Close()
			errR.Close()
		}
	})
	defer stopPipes()
	owned, err = s.controller.Start(jobCtx, job, gvisor.MeasuredGuestCommand{Command: "/provenance-measured-paper"}, inputs, authority, inR, outW, errW)
	inR.Close()
	outW.Close()
	errW.Close()
	if err != nil || owned == nil {
		return ErrService
	}
	diagnostics := make(chan struct{})
	var diagnosticErr error
	go func() {
		defer close(diagnostics)
		n, err := io.Copy(io.Discard, io.LimitReader(errR, (64<<10)+1))
		if n > 64<<10 {
			err = ErrService
		}
		if err != nil {
			cancel(ErrService)
		}
		diagnosticErr = err
	}()
	defer func() { errR.Close(); <-diagnostics }()
	if owned.Release(jobCtx) != nil || outR.SetReadDeadline(deadline) != nil || guestoutput.ReadStartup(outR) != nil {
		return ErrService
	}
	observation, err := owned.ObserveRuntime(jobCtx)
	if err != nil {
		return ErrService
	}
	raw, err := runtimeidentity.EncodeRootObservation(job, observation)
	if err != nil {
		return ErrService
	}
	// The live observation is sealed before release can be accepted. Send
	// it before supplying any configuration that lets the helper run Java.
	releaseAllowed.Store(true)
	if send.observation(raw) != nil {
		return ErrService
	}
	select {
	case <-jobCtx.Done():
		return ErrService
	case <-released:
	}
	if jobCtx.Err() != nil || (secretRequired && !secretExpiry.After(time.Now())) {
		return ErrService
	}
	bootstrap := plan.GuestConfiguration()
	if _, err := inW.Write(bootstrap); err != nil {
		return ErrService
	}
	if inW.Close() != nil {
		return ErrService
	}
	buffer := make([]byte, cc.MaximumPayload)
	total := 0
	var relayErr error
	for {
		n, err := outR.Read(buffer)
		if n > cc.MaximumResultBytes-total {
			relayErr = ErrService
			cancel(relayErr)
			break
		}
		total += n
		if n > 0 {
			if e := send.result(buffer[:n]); e != nil {
				relayErr = e
				cancel(e)
				break
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			relayErr = err
			cancel(ErrService)
			break
		}
	}
	// A cancelled caller still gets a bounded cleanup opportunity. No completed
	// receipt is sent unless the controller proves all owned resources retired.
	waitCtx, stopWait := context.WithDeadline(context.Background(), deadline.Add(15*time.Second))
	defer stopWait()
	stopDrain := context.AfterFunc(jobCtx, func() {
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-waitCtx.Done():
		case <-timer.C:
			stopWait()
		}
	})
	defer stopDrain()
	waitErr := owned.Wait(waitCtx)
	exit, infrastructure, err := owned.CompletedProcessOutcome()
	if err != nil {
		return ErrService
	}
	<-diagnostics
	// Exit 125 is reserved by the fixed Paper helper for preparation/internal
	// failure; Java exit 125 is mapped to 126 inside that measured helper.
	infrastructure = infrastructure || exit == 125 || relayErr != nil || diagnosticErr != nil || waitCtx.Err() != nil
	if waitErr != nil && !infrastructure {
		// CompletedProcessOutcome already distinguishes the exact ordinary exit
		// from other Wait errors; do not relabel plugin failure as infrastructure.
		if exit == 0 {
			infrastructure = true
		}
	}
	completion, err := cc.EncodeCompletion(exit, infrastructure)
	if s.fixtureCompletion != nil {
		s.fixtureCompletion(exit, infrastructure, waitErr, relayErr, diagnosticErr, context.Cause(jobCtx))
	}
	if err != nil {
		return ErrService
	}
	stopKeep()
	<-keepDone
	if send.completion(completion) != nil {
		return ErrService
	}
	return nil
}

func receiveAuthority(ctx context.Context, channel *cc.Channel, authority *np.AuthorityRoute) error {
	packet, err := receiveServicePacket(ctx, channel)
	if err != nil {
		return err
	}
	return applyAuthorityPacket(ctx, packet, authority)
}

func receiveServicePacket(ctx context.Context, channel *cc.Channel) (cc.Packet, error) {
	if ctx.Err() != nil {
		return cc.Packet{}, ErrService
	}
	deadline := time.Now().Add(25 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	packet, err := channel.Receive(deadline)
	if err != nil {
		return cc.Packet{}, ErrService
	}
	defer func() {
		for _, file := range packet.Files {
			_ = file.Close()
		}
	}()
	if len(packet.Files) != 0 {
		return cc.Packet{}, ErrService
	}
	return packet, nil
}

func applyAuthorityPacket(ctx context.Context, packet cc.Packet, authority *np.AuthorityRoute) error {
	if packet.Kind != cc.Reconcile {
		return ErrService
	}
	update, err := np.DecodeAuthorityUpdate(packet.Payload)
	if err != nil {
		return ErrService
	}
	if err := authority.Reconcile(ctx, update.Reconciliation, update.Features, update.CredentialExpiry); err != nil {
		return ErrService
	}
	return nil
}
