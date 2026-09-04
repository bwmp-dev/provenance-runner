package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	minimumHeartbeatInterval  = time.Second
	maximumHeartbeatInterval  = 5 * time.Minute
	minimumLeaseDuration      = time.Second
	maximumLeaseDuration      = 24 * time.Hour
	maximumCredentialLifetime = 366 * 24 * time.Hour
	maximumClockSkew          = 10 * time.Minute
	maximumHandshakeDuration  = 30 * time.Second
	maximumReasonBytes        = 1024
	initialReconnectDelay     = 250 * time.Millisecond
	maximumReconnectDelay     = 30 * time.Second
)

var ErrServerShutdown = errors.New("gateway requested runner shutdown")

type gatewayStream interface {
	Send(*runnerv1.RunnerMessage) error
	Recv() (*runnerv1.GatewayMessage, error)
	CloseSend() error
}

type streamConnector interface {
	connect(context.Context) (gatewayStream, error)
}

type RemoteWorker interface {
	Execute(context.Context, *runnerv1.JobSpecification, func(context.Context, execution.ExecutionStart) error) execution.Result
}

type permanentError struct {
	err error
}

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func permanent(format string, arguments ...any) error {
	return &permanentError{err: fmt.Errorf(format, arguments...)}
}

type Client struct {
	config    Config
	connector streamConnector
	worker    RemoteWorker
	journal   *journal
	close     func() error

	now              func() time.Time
	wait             func(context.Context, time.Duration) error
	handshakeTimeout time.Duration

	draining atomic.Bool

	workerMu          sync.Mutex
	workerRunning     bool
	workerCancel      context.CancelFunc
	workerWG          sync.WaitGroup
	startResponse     chan error
	workerEvents      chan workerEvent
	recovering        bool
	sessionGeneration atomic.Uint64
	ephemeralSequence atomic.Uint64

	uploadMu     sync.Mutex
	activeUpload *activeCompleteLogUpload
	logUploader  completeLogUploader

	restartEvidenceMu sync.Mutex
	restartEvidence   *restartEvidenceStore

	deferredMu           sync.Mutex
	deferredWorkerEvents []workerEvent
}

type workerEvent struct {
	start         chan error
	result        *execution.Result
	evidence      *workerEvidenceEvent
	finalEvidence *workerEvidenceEvent
	finalUsage    *workerEvidenceEvent
}

func New(config Config, rpc runnerv1.RunnerGatewayClient) (*Client, error) {
	return NewWithWorker(config, rpc, nil)
}

func NewWithWorker(config Config, rpc runnerv1.RunnerGatewayClient, worker RemoteWorker) (*Client, error) {
	if rpc == nil {
		return nil, errors.New("runner gateway client is required")
	}
	config = config.normalized()
	if err := config.validate(); err != nil {
		return nil, err
	}
	config.credential = bytes.Clone(config.credential)
	return newClientWithWorker(config, &generatedConnector{client: rpc}, worker)
}

func newClient(config Config, connector streamConnector) *Client {
	client, err := newClientWithWorker(config, connector, nil)
	if err != nil {
		panic(err)
	}
	return client
}

func newClientWithWorker(config Config, connector streamConnector, worker RemoteWorker) (*Client, error) {
	if config.credentialStore == nil && filepath.IsAbs(config.CredentialFile) {
		// Existing configurations retain legacy connectivity when the host lacks
		// the required Linux durability primitives. The feature is advertised
		// only when this anchored owner-only store opens successfully.
		config.credentialStore, _ = openDurableCredentialStore(config.CredentialFile)
	}
	journal, err := openJournal(config.journalFile)
	if err != nil {
		if config.credentialStore != nil {
			_ = config.credentialStore.Close()
		}
		return nil, err
	}
	client := &Client{
		config:           config,
		connector:        connector,
		worker:           worker,
		journal:          journal,
		now:              time.Now,
		wait:             waitContext,
		handshakeTimeout: maximumHandshakeDuration,
		workerEvents:     make(chan workerEvent, 64),
		logUploader:      newHTTPCompleteLogUploader(),
	}
	restartEvidence, err := openRestartEvidenceStore(config.journalFile, journal.snapshot().Active)
	if err != nil {
		if config.credentialStore != nil {
			_ = config.credentialStore.Close()
		}
		return nil, err
	}
	client.restartEvidence = restartEvidence
	client.recovering = journal.snapshot().Active != nil
	return client, nil
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	var result error
	c.restartEvidenceMu.Lock()
	if c.restartEvidence != nil {
		result = c.restartEvidence.close()
	}
	c.restartEvidenceMu.Unlock()
	if c.close != nil {
		result = errors.Join(result, c.close())
		c.close = nil
	}
	if c.config.credentialStore != nil {
		result = errors.Join(result, c.config.credentialStore.Close())
		c.config.credentialStore = nil
	}
	clear(c.config.credential)
	return result
}

func (c *Client) Drain() {
	if c != nil {
		c.draining.Store(true)
	}
}

func (c *Client) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	defer func() {
		c.stopWorker(context.Canceled)
		c.workerWG.Wait()
		c.discardQueuedWorkerEvents(context.Canceled)
	}()
	delay := initialReconnectDelay
	for {
		established, err := c.runSession(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !transient(err) {
			return sanitizeStreamError(err)
		}
		if errors.Is(err, errCredentialRotationReconnect) {
			delay = initialReconnectDelay
			continue
		}
		if established {
			delay = initialReconnectDelay
		}
		if err := c.wait(ctx, delay); err != nil {
			return err
		}
		if delay < maximumReconnectDelay {
			delay *= 2
			if delay > maximumReconnectDelay {
				delay = maximumReconnectDelay
			}
		}
	}
}

func (c *Client) runSession(ctx context.Context) (established bool, result error) {
	sessionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := c.connector.connect(sessionContext)
	if err != nil {
		return false, err
	}
	defer func() {
		if closeErr := stream.CloseSend(); result == nil {
			result = closeErr
		}
	}()

	sendRequests := make(chan streamSend)
	sendErrors := make(chan error, 1)
	go runStreamWriter(sessionContext, stream, sendRequests, sendErrors)
	send := func(message *runnerv1.RunnerMessage) error {
		response := make(chan error, 1)
		select {
		case sendRequests <- streamSend{message: message, response: response}:
		case <-sessionContext.Done():
			return sessionContext.Err()
		}
		select {
		case err := <-response:
			return err
		case <-sessionContext.Done():
			return sessionContext.Err()
		}
	}

	authenticate, err := c.authenticateMessage()
	if err != nil {
		return false, err
	}
	sendErr := send(authenticate)
	clear(authenticate.GetAuthenticate().ConnectionCredential)
	if sendErr != nil {
		return false, sendErr
	}
	type received struct {
		message *runnerv1.GatewayMessage
		err     error
	}
	receivedMessages := make(chan received)
	var receiver sync.WaitGroup
	receiver.Add(1)
	go func() {
		defer receiver.Done()
		for {
			message, receiveErr := stream.Recv()
			select {
			case receivedMessages <- received{message: message, err: receiveErr}:
			case <-sessionContext.Done():
				return
			}
			if receiveErr != nil {
				return
			}
		}
	}()
	defer func() {
		cancel()
		receiver.Wait()
	}()
	handshakeTimer := time.NewTimer(c.handshakeTimeout)
	var first *runnerv1.GatewayMessage
	select {
	case <-ctx.Done():
		handshakeTimer.Stop()
		return false, ctx.Err()
	case <-handshakeTimer.C:
		return false, status.Error(codes.DeadlineExceeded, "authentication handshake timed out")
	case received := <-receivedMessages:
		handshakeTimer.Stop()
		if received.err != nil {
			return false, received.err
		}
		first = received.message
	}
	now := c.now().UTC()
	authenticated, err := c.validateAuthenticated(first, now)
	if err != nil {
		return false, err
	}
	if err := c.reconcileCredentialRotationAfterAuthentication(); err != nil {
		return true, permanent("credential rotation reconnect state failed")
	}
	established = true
	generation := c.sessionGeneration.Add(1)
	capabilities, err := c.capabilitiesMessage()
	if err != nil {
		return true, err
	}
	if err := send(capabilities); err != nil {
		return true, err
	}
	jobCorrelationV1 := advertisedFeature(capabilities.GetCapabilities().GetFeatures(), runnerv1.ProtocolFeature_PROTOCOL_FEATURE_JOB_CORRELATION_V1)
	session := &clientSession{
		client:           c,
		authenticated:    authenticated,
		send:             send,
		jobCorrelationV1: jobCorrelationV1,
		seen:             make(map[string][sha256.Size]byte),
		rootContext:      ctx,
		cancelSession:    cancel,
		generation:       generation,
	}
	if err := session.rememberGatewayMessage(first); err != nil {
		return true, err
	}
	if pending := c.journal.snapshot().PendingMessage; len(pending) != 0 {
		message := new(runnerv1.RunnerMessage)
		if err := proto.Unmarshal(pending, message); err != nil {
			return true, permanent("decode pending runner message: %v", err)
		}
		if err := send(message); err != nil {
			return true, err
		}
	}
	if err := session.sendHeartbeat(now); err != nil {
		return true, err
	}

	heartbeatInterval := authenticated.HeartbeatInterval.AsDuration()
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	maintenanceInterval := 100 * time.Millisecond
	maintenance := time.NewTicker(maintenanceInterval)
	defer maintenance.Stop()
	expirationDelay := authenticated.CredentialExpiresAt.AsTime().Sub(now)
	expiration := time.NewTimer(expirationDelay)
	defer expiration.Stop()

	for {
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-expiration.C:
			return true, permanent("connection credential expired")
		case tick := <-ticker.C:
			if err := session.sendHeartbeat(tick.UTC()); err != nil {
				return true, err
			}
			if err := session.advance(tick.UTC()); err != nil {
				return true, err
			}
		case <-maintenance.C:
			if err := session.advance(c.now().UTC()); err != nil {
				return true, err
			}
		case worker := <-c.workerEvents:
			if err := session.handleWorkerEvent(worker); err != nil {
				return true, err
			}
		case err := <-sendErrors:
			return true, err
		case received := <-receivedMessages:
			if received.err != nil {
				return true, received.err
			}
			duplicate, err := session.gatewayMessageDuplicate(received.message)
			if err != nil {
				return true, err
			}
			if duplicate {
				continue
			}
			if err := session.handleGatewayMessage(received.message, c.now().UTC()); err != nil {
				return true, err
			}
			if session.heartbeatDeferred && len(c.journal.snapshot().PendingMessage) == 0 {
				if err := session.sendHeartbeat(c.now().UTC()); err != nil {
					return true, err
				}
			}
		}
	}
}

type streamSend struct {
	message  *runnerv1.RunnerMessage
	response chan error
}

func runStreamWriter(ctx context.Context, stream gatewayStream, requests <-chan streamSend, failures chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-requests:
			err := stream.Send(request.message)
			request.response <- err
			if err != nil {
				select {
				case failures <- err:
				default:
				}
				return
			}
		}
	}
}

func (c *Client) authenticateMessage() (*runnerv1.RunnerMessage, error) {
	message, err := c.runnerMessage()
	if err != nil {
		return nil, err
	}
	message.Payload = &runnerv1.RunnerMessage_Authenticate{Authenticate: &runnerv1.Authenticate{
		RunnerId:             c.config.RunnerID,
		InstanceId:           c.config.InstanceID,
		ConnectionCredential: bytes.Clone(c.config.credential),
		ProtocolVersion:      ProtocolVersion,
	}}
	return message, nil
}

func (c *Client) capabilitiesMessage() (*runnerv1.RunnerMessage, error) {
	capabilities := c.capabilities()
	if err := validateAdvertisedFeatures(capabilities.GetFeatures()); err != nil {
		return nil, err
	}
	message, err := c.runnerMessage()
	if err != nil {
		return nil, err
	}
	message.Payload = &runnerv1.RunnerMessage_Capabilities{Capabilities: capabilities}
	return message, nil
}

func (c *Client) heartbeatMessage(observedAt time.Time, activeLeases []*runnerv1.HeartbeatLease) (*runnerv1.RunnerMessage, error) {
	sequence, err := c.journal.nextHeartbeatSequence()
	if err != nil {
		return nil, err
	}
	heartbeat := &runnerv1.Heartbeat{
		Sequence:     sequence,
		Capacity:     c.capacity(),
		ActiveLeases: activeLeases,
		ObservedAt:   timestamppb.New(observedAt),
	}
	message, err := c.runnerMessage()
	if err != nil {
		return nil, err
	}
	message.Payload = &runnerv1.RunnerMessage_Heartbeat{Heartbeat: heartbeat}
	return message, nil
}

func (c *Client) runnerMessage() (*runnerv1.RunnerMessage, error) {
	now := c.now().UTC()
	sequence, err := c.journal.nextMessageSequence()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(c.config.InstanceID))
	return &runnerv1.RunnerMessage{
		MessageId: fmt.Sprintf("%x-%016x", digest[:12], sequence),
		SentAt:    timestamppb.New(now),
	}, nil
}

func (c *Client) capabilities() *runnerv1.Capabilities {
	resources := c.config.Resources
	features := []runnerv1.ProtocolFeature{runnerv1.ProtocolFeature_PROTOCOL_FEATURE_DURABLE_LEASE_ACKNOWLEDGEMENTS}
	if c.config.credentialStore != nil {
		features = append(features, runnerv1.ProtocolFeature_PROTOCOL_FEATURE_CREDENTIAL_ROTATION)
	}
	features = append(features, runnerv1.ProtocolFeature_PROTOCOL_FEATURE_JOB_CORRELATION_V1)
	return &runnerv1.Capabilities{
		RunnerVersion:    c.config.RunnerVersion,
		ProtocolVersions: []string{ProtocolVersion},
		OperatingSystem:  runnerv1.OperatingSystem_OPERATING_SYSTEM_LINUX,
		Architecture:     runnerv1.Architecture_ARCHITECTURE_AMD64,
		Sandboxes:        []runnerv1.SandboxKind{runnerv1.SandboxKind_SANDBOX_KIND_GVISOR},
		Providers:        []runnerv1.ServerProvider{runnerv1.ServerProvider_SERVER_PROVIDER_PAPER},
		Capacity:         c.capacity(),
		Policy: &runnerv1.RunnerPolicy{
			Sandboxes:              []runnerv1.SandboxKind{runnerv1.SandboxKind_SANDBOX_KIND_GVISOR},
			MaximumNetwork:         &runnerv1.NetworkPolicy{Mode: runnerv1.NetworkMode_NETWORK_MODE_NONE},
			MaximumResourcesPerJob: &runnerv1.ResourceLimits{CpuMillis: resources.CPUMillis, MemoryBytes: resources.MemoryBytes, DiskBytes: resources.DiskBytes, ProcessCount: resources.ProcessCount},
			MaximumConcurrentJobs:  1,
		},
		Features: features,
	}
}

func (c *Client) capacity() *runnerv1.Capacity {
	available := uint32(1)
	if c.draining.Load() || c.journal.snapshot().Active != nil || c.isWorkerRunning() {
		available = 0
	}
	return &runnerv1.Capacity{
		ConcurrentJobs: 1,
		AvailableJobs:  available,
		CpuMillis:      c.config.Resources.CPUMillis,
		MemoryBytes:    c.config.Resources.MemoryBytes,
		DiskBytes:      c.config.Resources.DiskBytes,
	}
}

func (c *Client) validateAuthenticated(message *runnerv1.GatewayMessage, now time.Time) (*runnerv1.Authenticated, error) {
	if err := validateGatewayEnvelope(message, now); err != nil {
		return nil, err
	}
	authenticated := message.GetAuthenticated()
	if authenticated == nil {
		return nil, permanent("first gateway message must be authenticated")
	}
	if authenticated.GetRunnerId() != c.config.RunnerID {
		return nil, permanent("authenticated runner scope does not match configured runnerId")
	}
	if err := validateUUID("authenticated.connectionId", authenticated.GetConnectionId()); err != nil {
		return nil, permanent("%v", err)
	}
	if authenticated.GetProtocolVersion() != ProtocolVersion {
		return nil, permanent("authenticated protocolVersion must be %q", ProtocolVersion)
	}
	if err := c.validateScope(authenticated.GetOrganizationScope()); err != nil {
		return nil, permanent("%v", err)
	}
	if err := validateTimestamp("authenticated.credentialExpiresAt", authenticated.GetCredentialExpiresAt()); err != nil {
		return nil, permanent("%v", err)
	}
	expiration := authenticated.GetCredentialExpiresAt().AsTime()
	if !expiration.After(now) || expiration.After(now.Add(maximumCredentialLifetime)) {
		return nil, permanent("authenticated.credentialExpiresAt must be in the future and within %s", maximumCredentialLifetime)
	}
	if err := validateDuration("authenticated.heartbeatInterval", authenticated.GetHeartbeatInterval(), minimumHeartbeatInterval, maximumHeartbeatInterval); err != nil {
		return nil, permanent("%v", err)
	}
	if err := validateDuration("authenticated.leaseDuration", authenticated.GetLeaseDuration(), minimumLeaseDuration, maximumLeaseDuration); err != nil {
		return nil, permanent("%v", err)
	}
	if err := validateTimestampNear("authenticated.serverTime", authenticated.GetServerTime(), now); err != nil {
		return nil, permanent("%v", err)
	}
	return authenticated, nil
}

func (c *Client) validateScope(scope *runnerv1.OrganizationScope) error {
	if scope == nil {
		return errors.New("authenticated.organizationScope is required")
	}
	switch c.config.ExpectedScope.Kind {
	case ScopePlatform:
		if scope.GetPlatform() == nil {
			return errors.New("authenticated organization scope does not match expected platform scope")
		}
	case ScopeOrganization:
		if scope.GetOrganizationId() != c.config.ExpectedScope.OrganizationID {
			return errors.New("authenticated organization scope does not match expected organization")
		}
	default:
		return errors.New("configured expected scope is invalid")
	}
	return nil
}

func validateGatewayEnvelope(message *runnerv1.GatewayMessage, now time.Time) error {
	if message == nil {
		return permanent("gateway message is nil")
	}
	if err := validateIdentifier("gateway messageId", message.GetMessageId(), maximumIdentifierBytes); err != nil {
		return permanent("%v", err)
	}
	if err := validateTimestampNear("gateway sentAt", message.GetSentAt(), now); err != nil {
		return permanent("%v", err)
	}
	if message.GetPayload() == nil {
		return permanent("gateway message payload is required")
	}
	return nil
}

func validateTimestamp(field string, value *timestamppb.Timestamp) error {
	if value == nil {
		return fmt.Errorf("%s is required", field)
	}
	if err := value.CheckValid(); err != nil {
		return fmt.Errorf("%s is invalid: %w", field, err)
	}
	return nil
}

func validateTimestampNear(field string, value *timestamppb.Timestamp, now time.Time) error {
	if err := validateTimestamp(field, value); err != nil {
		return err
	}
	difference := value.AsTime().Sub(now)
	if difference < -maximumClockSkew || difference > maximumClockSkew {
		return fmt.Errorf("%s must be within %s of local time", field, maximumClockSkew)
	}
	return nil
}

func validateDuration(field string, value *durationpb.Duration, minimum, maximum time.Duration) error {
	if value == nil {
		return fmt.Errorf("%s is required", field)
	}
	if err := value.CheckValid(); err != nil {
		return fmt.Errorf("%s is invalid: %w", field, err)
	}
	duration := value.AsDuration()
	if duration < minimum || duration > maximum {
		return fmt.Errorf("%s must be between %s and %s", field, minimum, maximum)
	}
	return nil
}

func transient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errCredentialRotationReconnect) {
		return true
	}
	var permanentFailure *permanentError
	if errors.As(err, &permanentFailure) {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	var networkFailure net.Error
	if errors.As(err, &networkFailure) {
		return networkFailure.Timeout() || networkFailure.Temporary()
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded:
		return true
	default:
		return false
	}
}

func sanitizeStreamError(err error) error {
	var localFailure *permanentError
	if errors.As(err, &localFailure) {
		return err
	}
	if code := status.Code(err); code != codes.OK {
		return status.Error(code, "gateway stream stopped")
	}
	return errors.New("gateway stream stopped")
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
