package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	maximumGatewayMessages    = 64
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
	close     func() error

	now              func() time.Time
	wait             func(context.Context, time.Duration) error
	handshakeTimeout time.Duration

	draining          atomic.Bool
	messageSequence   atomic.Uint64
	heartbeatSequence atomic.Uint64
}

func New(config Config, rpc runnerv1.RunnerGatewayClient) (*Client, error) {
	if rpc == nil {
		return nil, errors.New("runner gateway client is required")
	}
	config = config.normalized()
	if err := config.validate(); err != nil {
		return nil, err
	}
	config.credential = bytes.Clone(config.credential)
	return newClient(config, &generatedConnector{client: rpc}), nil
}

func newClient(config Config, connector streamConnector) *Client {
	return &Client{
		config:           config,
		connector:        connector,
		now:              time.Now,
		wait:             waitContext,
		handshakeTimeout: maximumHandshakeDuration,
	}
}

func (c *Client) Close() error {
	if c == nil || c.close == nil {
		return nil
	}
	return c.close()
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

	if err := stream.Send(c.authenticateMessage()); err != nil {
		return false, err
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
	established = true
	if err := stream.Send(c.capabilitiesMessage()); err != nil {
		return true, err
	}
	heartbeat, err := c.heartbeatMessage(now, nil)
	if err != nil {
		return true, err
	}
	if err := stream.Send(heartbeat); err != nil {
		return true, err
	}
	seenGatewayMessages := map[string]struct{}{first.GetMessageId(): {}}

	heartbeatInterval := authenticated.HeartbeatInterval.AsDuration()
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
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
			heartbeat, err := c.heartbeatMessage(tick.UTC(), nil)
			if err != nil {
				return true, err
			}
			if err := stream.Send(heartbeat); err != nil {
				return true, err
			}
		case received := <-receivedMessages:
			if received.err != nil {
				return true, received.err
			}
			messageID := received.message.GetMessageId()
			if _, duplicate := seenGatewayMessages[messageID]; duplicate {
				return true, permanent("gateway messageId was reused")
			}
			if len(seenGatewayMessages) >= maximumGatewayMessages {
				return true, permanent("gateway sent more than %d control messages in one connection", maximumGatewayMessages)
			}
			seenGatewayMessages[messageID] = struct{}{}
			sendHeartbeat, err := c.handleGatewayMessage(received.message, c.now().UTC())
			if err != nil {
				return true, err
			}
			if sendHeartbeat {
				heartbeat, err := c.heartbeatMessage(c.now().UTC(), nil)
				if err != nil {
					return true, err
				}
				if err := stream.Send(heartbeat); err != nil {
					return true, err
				}
			}
		}
	}
}

func (c *Client) authenticateMessage() *runnerv1.RunnerMessage {
	message := c.runnerMessage()
	message.Payload = &runnerv1.RunnerMessage_Authenticate{Authenticate: &runnerv1.Authenticate{
		RunnerId:             c.config.RunnerID,
		InstanceId:           c.config.InstanceID,
		ConnectionCredential: bytes.Clone(c.config.credential),
		ProtocolVersion:      ProtocolVersion,
	}}
	return message
}

func (c *Client) capabilitiesMessage() *runnerv1.RunnerMessage {
	message := c.runnerMessage()
	message.Payload = &runnerv1.RunnerMessage_Capabilities{Capabilities: c.capabilities()}
	return message
}

func (c *Client) heartbeatMessage(observedAt time.Time, activeLeases []*runnerv1.HeartbeatLease) (*runnerv1.RunnerMessage, error) {
	if len(activeLeases) != 0 {
		return nil, permanent("active leases are not supported by this runner alpha")
	}
	heartbeat := &runnerv1.Heartbeat{
		Sequence:     c.heartbeatSequence.Add(1),
		Capacity:     c.capacity(),
		ActiveLeases: activeLeases,
		ObservedAt:   timestamppb.New(observedAt),
	}
	message := c.runnerMessage()
	message.Payload = &runnerv1.RunnerMessage_Heartbeat{Heartbeat: heartbeat}
	return message, nil
}

func (c *Client) runnerMessage() *runnerv1.RunnerMessage {
	now := c.now().UTC()
	sequence := c.messageSequence.Add(1)
	digest := sha256.Sum256([]byte(c.config.InstanceID))
	return &runnerv1.RunnerMessage{
		MessageId: fmt.Sprintf("%x-%016x", digest[:12], sequence),
		SentAt:    timestamppb.New(now),
	}
}

func (c *Client) capabilities() *runnerv1.Capabilities {
	resources := c.config.Resources
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
	}
}

func (c *Client) capacity() *runnerv1.Capacity {
	available := uint32(1)
	if c.draining.Load() {
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

func (c *Client) handleGatewayMessage(message *runnerv1.GatewayMessage, now time.Time) (bool, error) {
	if err := validateGatewayEnvelope(message, now); err != nil {
		return false, err
	}
	switch {
	case message.GetDrain() != nil:
		drain := message.GetDrain()
		if err := validateIdentifier("drain.drainId", drain.GetDrainId(), maximumIdentifierBytes); err != nil {
			return false, permanent("%v", err)
		}
		if len(drain.GetReason()) > maximumReasonBytes {
			return false, permanent("drain.reason must be at most %d bytes", maximumReasonBytes)
		}
		if err := validateTimestamp("drain.deadline", drain.GetDeadline()); err != nil {
			return false, permanent("%v", err)
		}
		c.Drain()
		return true, nil
	case message.GetShutdown() != nil:
		shutdown := message.GetShutdown()
		if err := validateIdentifier("shutdown.shutdownId", shutdown.GetShutdownId(), maximumIdentifierBytes); err != nil {
			return false, permanent("%v", err)
		}
		if len(shutdown.GetReason()) > maximumReasonBytes {
			return false, permanent("shutdown.reason must be at most %d bytes", maximumReasonBytes)
		}
		if err := validateTimestamp("shutdown.deadline", shutdown.GetDeadline()); err != nil {
			return false, permanent("%v", err)
		}
		return false, permanent("%w", ErrServerShutdown)
	case message.GetOffer() != nil:
		return false, permanent("lease offers are not supported by this runner alpha")
	case message.GetCancel() != nil:
		return false, permanent("job cancellation is not supported by this runner alpha")
	case message.GetPolicyUpdate() != nil:
		return false, permanent("policy updates are not supported by this runner alpha")
	case message.GetCredentialRotation() != nil:
		return false, permanent("credential rotation is not supported by this runner alpha")
	case message.GetAuthenticated() != nil:
		return false, permanent("authenticated may only be sent as the first gateway message")
	default:
		return false, permanent("gateway message payload is missing or unsupported")
	}
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
