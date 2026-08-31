package gatewayclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	testRunnerID       = "50000000-0000-0000-0000-000000000001"
	testOrganizationID = "40000000-0000-0000-0000-000000000001"
)

func TestPlatformGatewayWireProtocolCompatibility(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := newClient(validConfig(), nil)
	if got := client.authenticateMessage().GetAuthenticate().GetProtocolVersion(); got != "1" {
		t.Fatalf("Authenticate.protocol_version = %q, want platform gateway literal 1", got)
	}
	protocols := client.capabilitiesMessage().GetCapabilities().GetProtocolVersions()
	if len(protocols) != 1 || protocols[0] != "1" {
		t.Fatalf("Capabilities.protocol_versions = %v, want [1]", protocols)
	}
	if _, err := client.validateAuthenticated(authenticatedMessage(now, platformScope()), now); err != nil {
		t.Fatalf("platform gateway Authenticated literal rejected: %v", err)
	}
}

func TestHandshakeCapabilitiesHeartbeatAndDrainOrdering(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	var received []*runnerv1.RunnerMessage
	server := &testGateway{connect: func(stream grpc.BidiStreamingServer[runnerv1.RunnerMessage, runnerv1.GatewayMessage]) error {
		for range 3 {
			message, err := stream.Recv()
			if err != nil {
				return err
			}
			received = append(received, message)
			if len(received) == 1 {
				if err := stream.Send(authenticatedMessage(now, platformScope())); err != nil {
					return err
				}
			}
		}
		if err := stream.Send(gatewayMessage(now, &runnerv1.GatewayMessage_Drain{Drain: &runnerv1.DrainRunner{
			DrainId: "drain-1", Reason: "maintenance", Deadline: timestamppb.New(now.Add(time.Minute)),
		}})); err != nil {
			return err
		}
		drained, err := stream.Recv()
		if err != nil {
			return err
		}
		received = append(received, drained)
		return stream.Send(gatewayMessage(now, &runnerv1.GatewayMessage_Shutdown{Shutdown: &runnerv1.ShutdownRunner{
			ShutdownId: "shutdown-1", Deadline: timestamppb.New(now.Add(time.Minute)),
		}}))
	}}
	client, closeConnection := bufconnClient(t, server)
	defer closeConnection()
	client.now = func() time.Time { return now }

	err := client.Run(context.Background())
	if !errors.Is(err, ErrServerShutdown) {
		t.Fatalf("Run() error = %v, want ErrServerShutdown", err)
	}
	if len(received) != 4 {
		t.Fatalf("received %d messages, want 4", len(received))
	}
	if got := received[0].GetAuthenticate(); got == nil || got.GetRunnerId() != testRunnerID || got.GetInstanceId() != "instance-1" || got.GetProtocolVersion() != "1" || !bytes.Equal(got.GetConnectionCredential(), []byte("credential")) {
		t.Fatalf("authenticate = %#v", got)
	}
	capabilities := received[1].GetCapabilities()
	if capabilities == nil || capabilities.GetRunnerVersion() != "test" || capabilities.GetOperatingSystem() != runnerv1.OperatingSystem_OPERATING_SYSTEM_LINUX || capabilities.GetArchitecture() != runnerv1.Architecture_ARCHITECTURE_AMD64 {
		t.Fatalf("capabilities = %#v", capabilities)
	}
	if fmt.Sprint(capabilities.GetProtocolVersions()) != "[1]" || fmt.Sprint(capabilities.GetSandboxes()) != "[SANDBOX_KIND_GVISOR]" || fmt.Sprint(capabilities.GetProviders()) != "[SERVER_PROVIDER_PAPER]" {
		t.Fatalf("capability lists = protocols %v sandboxes %v providers %v", capabilities.GetProtocolVersions(), capabilities.GetSandboxes(), capabilities.GetProviders())
	}
	if capabilities.GetPolicy().GetMaximumNetwork().GetMode() != runnerv1.NetworkMode_NETWORK_MODE_NONE || capabilities.GetPolicy().GetMaximumConcurrentJobs() != 1 {
		t.Fatalf("policy = %#v", capabilities.GetPolicy())
	}
	firstHeartbeat := received[2].GetHeartbeat()
	drainedHeartbeat := received[3].GetHeartbeat()
	if firstHeartbeat == nil || firstHeartbeat.GetSequence() != 1 || len(firstHeartbeat.GetActiveLeases()) != 0 || firstHeartbeat.GetCapacity().GetAvailableJobs() != 1 || !firstHeartbeat.GetObservedAt().AsTime().Equal(now) {
		t.Fatalf("first heartbeat = %#v", firstHeartbeat)
	}
	if drainedHeartbeat == nil || drainedHeartbeat.GetSequence() != 2 || drainedHeartbeat.GetCapacity().GetAvailableJobs() != 0 || drainedHeartbeat.GetCapacity().GetConcurrentJobs() != 1 {
		t.Fatalf("drained heartbeat = %#v", drainedHeartbeat)
	}
	ids := map[string]struct{}{}
	for _, message := range received {
		if _, duplicate := ids[message.GetMessageId()]; duplicate {
			t.Fatalf("duplicate message id %q", message.GetMessageId())
		}
		ids[message.GetMessageId()] = struct{}{}
		if len(message.GetMessageId()) > maximumIdentifierBytes || message.GetSentAt() == nil {
			t.Fatalf("invalid envelope %#v", message)
		}
	}
}

func TestAuthenticatedValidationFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	tests := map[string]func(*runnerv1.GatewayMessage){
		"wrong protocol": func(message *runnerv1.GatewayMessage) { message.GetAuthenticated().ProtocolVersion = "v2" },
		"wrong runner":   func(message *runnerv1.GatewayMessage) { message.GetAuthenticated().RunnerId = "other" },
		"wrong scope": func(message *runnerv1.GatewayMessage) {
			message.GetAuthenticated().OrganizationScope = organizationScope(testOrganizationID)
		},
		"invalid connection id": func(message *runnerv1.GatewayMessage) { message.GetAuthenticated().ConnectionId = "connection-1" },
		"expired credential": func(message *runnerv1.GatewayMessage) {
			message.GetAuthenticated().CredentialExpiresAt = timestamppb.New(now)
		},
		"heartbeat too short": func(message *runnerv1.GatewayMessage) {
			message.GetAuthenticated().HeartbeatInterval = durationpb.New(time.Millisecond)
		},
		"lease too long": func(message *runnerv1.GatewayMessage) {
			message.GetAuthenticated().LeaseDuration = durationpb.New(maximumLeaseDuration + time.Second)
		},
		"server clock skew": func(message *runnerv1.GatewayMessage) {
			message.GetAuthenticated().ServerTime = timestamppb.New(now.Add(maximumClockSkew + time.Second))
		},
		"missing envelope": func(message *runnerv1.GatewayMessage) { message.MessageId = "" },
		"unexpected first payload": func(message *runnerv1.GatewayMessage) {
			message.Payload = &runnerv1.GatewayMessage_Drain{Drain: &runnerv1.DrainRunner{}}
		},
	}
	client := newClient(validConfig(), nil)
	client.now = func() time.Time { return now }
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			message := authenticatedMessage(now, platformScope())
			mutate(message)
			if _, err := client.validateAuthenticated(message, now); err == nil || transient(err) {
				t.Fatalf("validateAuthenticated() error = %v, want permanent error", err)
			}
		})
	}
}

func TestOrganizationScopeMustMatchExactly(t *testing.T) {
	now := time.Now().UTC()
	config := validConfig()
	config.ExpectedScope = ExpectedScope{Kind: ScopeOrganization, OrganizationID: testOrganizationID}
	client := newClient(config, nil)
	if _, err := client.validateAuthenticated(authenticatedMessage(now, organizationScope(testOrganizationID)), now); err != nil {
		t.Fatalf("matching organization scope rejected: %v", err)
	}
	for _, scope := range []*runnerv1.OrganizationScope{platformScope(), organizationScope("40000000-0000-0000-0000-000000000002"), nil} {
		if _, err := client.validateAuthenticated(authenticatedMessage(now, scope), now); err == nil {
			t.Fatalf("scope %#v accepted", scope)
		}
	}
}

func TestUnsupportedMessagesAndActiveLeasesFailClosed(t *testing.T) {
	now := time.Now().UTC()
	client := newClient(validConfig(), nil)
	messages := []*runnerv1.GatewayMessage{
		gatewayMessage(now, &runnerv1.GatewayMessage_Offer{Offer: &runnerv1.LeaseOffer{}}),
		gatewayMessage(now, &runnerv1.GatewayMessage_Cancel{Cancel: &runnerv1.CancelJob{}}),
		gatewayMessage(now, &runnerv1.GatewayMessage_PolicyUpdate{PolicyUpdate: &runnerv1.PolicyUpdate{}}),
		gatewayMessage(now, &runnerv1.GatewayMessage_CredentialRotation{CredentialRotation: &runnerv1.RotateCredential{}}),
	}
	for _, message := range messages {
		if _, err := client.handleGatewayMessage(message, now); err == nil || transient(err) {
			t.Fatalf("payload %T error = %v, want permanent", message.GetPayload(), err)
		}
	}
	if message, err := client.heartbeatMessage(now, []*runnerv1.HeartbeatLease{{}}); err == nil || message != nil {
		t.Fatalf("heartbeatMessage(nonempty) = %#v, %v", message, err)
	}
}

func TestTransientReconnectAndPermanentStatuses(t *testing.T) {
	now := time.Now().UTC()
	connector := &scriptedConnector{results: []connectResult{
		{err: status.Error(codes.Unavailable, "temporary")},
		{err: status.Error(codes.DeadlineExceeded, "temporary")},
		{stream: scriptedSession(now)},
	}}
	client := newClient(validConfig(), connector)
	client.now = func() time.Time { return now }
	var waits []time.Duration
	client.wait = func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		return nil
	}
	if err := client.Run(context.Background()); !errors.Is(err, ErrServerShutdown) {
		t.Fatalf("Run() error = %v", err)
	}
	if connector.calls.Load() != 3 || fmt.Sprint(waits) != "[250ms 500ms]" {
		t.Fatalf("connect calls = %d, waits = %v", connector.calls.Load(), waits)
	}

	for _, code := range []codes.Code{codes.Unauthenticated, codes.PermissionDenied, codes.InvalidArgument, codes.Aborted, codes.ResourceExhausted} {
		t.Run(code.String(), func(t *testing.T) {
			connector := &scriptedConnector{results: []connectResult{{err: status.Error(code, "credential-secret")}}}
			client := newClient(validConfig(), connector)
			client.wait = func(context.Context, time.Duration) error { t.Fatal("wait called for permanent status"); return nil }
			if err := client.Run(context.Background()); status.Code(err) != code || strings.Contains(err.Error(), "credential-secret") {
				t.Fatalf("Run() error = %v", err)
			}
			if connector.calls.Load() != 1 {
				t.Fatalf("connect calls = %d", connector.calls.Load())
			}
		})
	}
}

func TestHandshakeTimeoutReconnectsWithoutLeakingReceiver(t *testing.T) {
	now := time.Now().UTC()
	connector := &scriptedConnector{results: []connectResult{
		{stream: newScriptedStream(context.Background())},
		{stream: scriptedSession(now)},
	}}
	client := newClient(validConfig(), connector)
	client.now = func() time.Time { return now }
	client.handshakeTimeout = 10 * time.Millisecond
	client.wait = func(context.Context, time.Duration) error { return nil }
	if err := client.Run(context.Background()); !errors.Is(err, ErrServerShutdown) {
		t.Fatalf("Run() error = %v", err)
	}
	if connector.calls.Load() != 2 {
		t.Fatalf("connect calls = %d", connector.calls.Load())
	}
}

func TestCredentialExpiryAndCancellationStopSession(t *testing.T) {
	now := time.Now().UTC()
	expires := authenticatedMessage(now, platformScope())
	expires.GetAuthenticated().CredentialExpiresAt = timestamppb.New(now.Add(20 * time.Millisecond))
	expiringStream := newScriptedStream(context.Background(), expires)
	client := newClient(validConfig(), &scriptedConnector{results: []connectResult{{stream: expiringStream}}})
	client.now = func() time.Time { return now }
	if err := client.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Run() expiry error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stream := newScriptedStream(ctx, authenticatedMessage(now, platformScope()))
	client = newClient(validConfig(), &scriptedConnector{results: []connectResult{{stream: stream}}})
	client.now = func() time.Time { return now }
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	waitForSentMessages(t, stream, 3)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

func TestCapabilitiesAndCredentialAreMutationIsolated(t *testing.T) {
	config := validConfig()
	client := newClient(config, nil)
	authenticate := client.authenticateMessage().GetAuthenticate()
	authenticate.ConnectionCredential[0] = 'Y'
	if got := string(client.authenticateMessage().GetAuthenticate().GetConnectionCredential()); got != "credential" {
		t.Fatalf("credential clone = %q", got)
	}
	first := client.capabilities()
	first.ProtocolVersions[0] = "mutated"
	first.Capacity.AvailableJobs = 99
	first.Policy.MaximumNetwork.Mode = runnerv1.NetworkMode_NETWORK_MODE_UNRESTRICTED
	second := client.capabilities()
	if second.GetProtocolVersions()[0] != ProtocolVersion || second.GetCapacity().GetAvailableJobs() != 1 || second.GetPolicy().GetMaximumNetwork().GetMode() != runnerv1.NetworkMode_NETWORK_MODE_NONE {
		t.Fatalf("capabilities retained mutation: %#v", second)
	}
}

func TestConfigIsStrictAndBounded(t *testing.T) {
	valid := validConfigJSON("credential")
	if _, err := decodeConfig([]byte(valid)); err != nil {
		t.Fatalf("decodeConfig(valid): %v", err)
	}
	tests := []string{
		strings.Replace(valid, `"gatewayAddress":"gateway.example:443"`, `"gatewayAddress":"https://gateway.example:443"`, 1),
		strings.Replace(valid, `"gatewayAddress":"gateway.example:443"`, `"gatewayAddress":"bad_host:443"`, 1),
		strings.Replace(valid, fmt.Sprintf(`"runnerId":%q`, testRunnerID), `"runnerId":"runner-1"`, 1),
		strings.Replace(valid, `"kind":"platform"`, `"kind":"platform","organizationId":"org"`, 1),
		strings.Replace(valid, `"cpuMillis":1000`, `"cpuMillis":0`, 1),
		strings.TrimSuffix(valid, "}") + `,"unknown":true}`,
		valid + `{}`,
	}
	for _, input := range tests {
		if _, err := decodeConfig([]byte(input)); err == nil {
			t.Fatalf("decodeConfig(%s) succeeded", input)
		}
	}
	unicodeInstance := validConfig()
	unicodeInstance.InstanceID = "instance-世界"
	if err := unicodeInstance.validate(); err != nil {
		t.Fatalf("server-compatible UTF-8 instanceId rejected: %v", err)
	}
	organization := validConfig()
	organization.ExpectedScope = ExpectedScope{Kind: ScopeOrganization, OrganizationID: "org-1"}
	if err := organization.validate(); err == nil || !strings.Contains(err.Error(), "UUID") {
		t.Fatalf("non-UUID organization scope error = %v", err)
	}
	credentialBoundary := validConfig()
	credentialBoundary.credential = bytes.Repeat([]byte("x"), MaximumCredentialBytes)
	if err := credentialBoundary.validate(); err != nil {
		t.Fatalf("maximum-size credential rejected: %v", err)
	}
	credentialBoundary.credential = append(credentialBoundary.credential, 'x')
	if err := credentialBoundary.validate(); err == nil {
		t.Fatal("oversized credential accepted")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose owner-only file mode bits; connect is Linux/amd64-only")
	}

	directory := t.TempDir()
	credentialPath := filepath.Join(directory, "credential")
	if err := os.WriteFile(credentialPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(credentialPath, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "connect.json")
	if err := os.WriteFile(configPath, []byte(validConfigJSON("credential")), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(configPath, "test")
	if err != nil {
		t.Fatalf("LoadConfig(): %v (mode %s)", err, fileMode(t, credentialPath))
	}
	if !bytes.Equal(config.credential, []byte("secret")) {
		t.Fatalf("credential = %q", config.credential)
	}
	if err := os.WriteFile(credentialPath, bytes.Repeat([]byte("x"), MaximumCredentialBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	if config, err := LoadConfig(configPath, "test"); err != nil || len(config.credential) != MaximumCredentialBytes {
		t.Fatalf("LoadConfig(maximum credential) = %d bytes, %v", len(config.credential), err)
	}
	if err := os.Chmod(credentialPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath, "test"); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("LoadConfig(world readable) error = %v", err)
	}
	if err := os.WriteFile(credentialPath, bytes.Repeat([]byte("x"), MaximumCredentialBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(credentialPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath, "test"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("LoadConfig(oversized) error = %v", err)
	}
	oversizedConfig := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(oversizedConfig, bytes.Repeat([]byte("x"), MaximumConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(oversizedConfig, "test"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("LoadConfig(oversized config) error = %v", err)
	}
	targetPath := filepath.Join(directory, "credential-target")
	if err := os.WriteFile(targetPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "credential-link")
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(validConfigJSON("credential-link")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath, "test"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("LoadConfig(symlink credential) error = %v", err)
	}
}

func TestGRPCReceiveMessageLimitFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	server := &testGateway{connect: func(stream grpc.BidiStreamingServer[runnerv1.RunnerMessage, runnerv1.GatewayMessage]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(authenticatedMessage(now, platformScope())); err != nil {
			return err
		}
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if _, err := stream.Recv(); err != nil {
			return err
		}
		return stream.Send(gatewayMessage(now, &runnerv1.GatewayMessage_Drain{Drain: &runnerv1.DrainRunner{
			DrainId: "drain", Reason: strings.Repeat("x", MaximumMessageBytes), Deadline: timestamppb.New(now.Add(time.Minute)),
		}}))
	}}
	client, closeConnection := bufconnClient(t, server)
	defer closeConnection()
	client.now = func() time.Time { return now }
	err := client.Run(context.Background())
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("Run() error = %v, want ResourceExhausted", err)
	}
}

func TestDuplicateGatewayMessageIDFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	server := &testGateway{connect: func(stream grpc.BidiStreamingServer[runnerv1.RunnerMessage, runnerv1.GatewayMessage]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		authenticated := authenticatedMessage(now, platformScope())
		authenticated.MessageId = "reused"
		if err := stream.Send(authenticated); err != nil {
			return err
		}
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if _, err := stream.Recv(); err != nil {
			return err
		}
		drain := gatewayMessage(now, &runnerv1.GatewayMessage_Drain{Drain: &runnerv1.DrainRunner{DrainId: "drain", Deadline: timestamppb.New(now.Add(time.Minute))}})
		drain.MessageId = "reused"
		return stream.Send(drain)
	}}
	client, closeConnection := bufconnClient(t, server)
	defer closeConnection()
	client.now = func() time.Time { return now }
	if err := client.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "reused") {
		t.Fatalf("Run() error = %v", err)
	}
}

func validConfig() Config {
	return Config{
		SchemaVersion:  ConfigSchemaVersion,
		GatewayAddress: "gateway.example:443",
		RunnerID:       testRunnerID,
		InstanceID:     "instance-1",
		CredentialFile: "credential",
		ExpectedScope:  ExpectedScope{Kind: ScopePlatform},
		Resources:      Resources{CPUMillis: 1000, MemoryBytes: 1 << 30, DiskBytes: 2 << 30, ProcessCount: 64},
		RunnerVersion:  "test",
		credential:     []byte("credential"),
	}
}

func validConfigJSON(credential string) string {
	return fmt.Sprintf(`{"schemaVersion":%q,"gatewayAddress":"gateway.example:443","runnerId":%q,"instanceId":"instance-1","credentialFile":%q,"expectedScope":{"kind":"platform"},"resources":{"cpuMillis":1000,"memoryBytes":1073741824,"diskBytes":2147483648,"processCount":64}}`, ConfigSchemaVersion, testRunnerID, credential)
}

func authenticatedMessage(now time.Time, scope *runnerv1.OrganizationScope) *runnerv1.GatewayMessage {
	return gatewayMessage(now, &runnerv1.GatewayMessage_Authenticated{Authenticated: &runnerv1.Authenticated{
		RunnerId:            testRunnerID,
		ConnectionId:        "60000000-0000-0000-0000-000000000001",
		OrganizationScope:   scope,
		CredentialExpiresAt: timestamppb.New(now.Add(time.Hour)),
		HeartbeatInterval:   durationpb.New(time.Minute),
		LeaseDuration:       durationpb.New(time.Minute),
		ServerTime:          timestamppb.New(now),
		ProtocolVersion:     "1",
	}})
}

func gatewayMessage(now time.Time, payload any) *runnerv1.GatewayMessage {
	message := &runnerv1.GatewayMessage{SentAt: timestamppb.New(now)}
	switch payload := payload.(type) {
	case *runnerv1.GatewayMessage_Authenticated:
		message.MessageId = "gateway-authenticated"
		message.Payload = payload
	case *runnerv1.GatewayMessage_Offer:
		message.MessageId = "gateway-offer"
		message.Payload = payload
	case *runnerv1.GatewayMessage_Cancel:
		message.MessageId = "gateway-cancel"
		message.Payload = payload
	case *runnerv1.GatewayMessage_Drain:
		message.MessageId = "gateway-drain"
		message.Payload = payload
	case *runnerv1.GatewayMessage_PolicyUpdate:
		message.MessageId = "gateway-policy"
		message.Payload = payload
	case *runnerv1.GatewayMessage_CredentialRotation:
		message.MessageId = "gateway-rotation"
		message.Payload = payload
	case *runnerv1.GatewayMessage_Shutdown:
		message.MessageId = "gateway-shutdown"
		message.Payload = payload
	default:
		panic(fmt.Sprintf("unsupported test payload %T", payload))
	}
	return message
}

func platformScope() *runnerv1.OrganizationScope {
	return &runnerv1.OrganizationScope{Scope: &runnerv1.OrganizationScope_Platform{Platform: &emptypb.Empty{}}}
}

func organizationScope(id string) *runnerv1.OrganizationScope {
	return &runnerv1.OrganizationScope{Scope: &runnerv1.OrganizationScope_OrganizationId{OrganizationId: id}}
}

type testGateway struct {
	runnerv1.UnimplementedRunnerGatewayServer
	connect func(grpc.BidiStreamingServer[runnerv1.RunnerMessage, runnerv1.GatewayMessage]) error
}

func (g *testGateway) Connect(stream grpc.BidiStreamingServer[runnerv1.RunnerMessage, runnerv1.GatewayMessage]) error {
	return g.connect(stream)
}

func bufconnClient(t *testing.T, gateway runnerv1.RunnerGatewayServer) (*Client, func()) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	runnerv1.RegisterRunnerGatewayServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///bufconn", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(validConfig(), runnerv1.NewRunnerGatewayClient(connection))
	if err != nil {
		t.Fatal(err)
	}
	return client, func() {
		_ = connection.Close()
		server.Stop()
		_ = listener.Close()
	}
}

type receiveResult struct {
	message *runnerv1.GatewayMessage
	err     error
}

type scriptedStream struct {
	ctx      context.Context
	receives chan receiveResult
	mu       sync.Mutex
	sent     []*runnerv1.RunnerMessage
}

func newScriptedStream(ctx context.Context, messages ...*runnerv1.GatewayMessage) *scriptedStream {
	receives := make(chan receiveResult, len(messages)+1)
	for _, message := range messages {
		receives <- receiveResult{message: message}
	}
	return &scriptedStream{ctx: ctx, receives: receives}
}

func (s *scriptedStream) Send(message *runnerv1.RunnerMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, message)
	return nil
}

func (s *scriptedStream) Recv() (*runnerv1.GatewayMessage, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case result := <-s.receives:
		return result.message, result.err
	}
}

func (s *scriptedStream) CloseSend() error { return nil }

type connectResult struct {
	stream gatewayStream
	err    error
}

type scriptedConnector struct {
	results []connectResult
	calls   atomic.Uint32
}

func (c *scriptedConnector) connect(ctx context.Context) (gatewayStream, error) {
	index := int(c.calls.Add(1)) - 1
	if index >= len(c.results) {
		return nil, errors.New("unexpected connect")
	}
	result := c.results[index]
	if stream, ok := result.stream.(*scriptedStream); ok {
		stream.ctx = ctx
	}
	return result.stream, result.err
}

func scriptedSession(now time.Time) *scriptedStream {
	return newScriptedStream(context.Background(),
		authenticatedMessage(now, platformScope()),
		gatewayMessage(now, &runnerv1.GatewayMessage_Shutdown{Shutdown: &runnerv1.ShutdownRunner{ShutdownId: "shutdown", Deadline: timestamppb.New(now.Add(time.Minute))}}),
	)
}

func waitForSentMessages(t *testing.T, stream *scriptedStream, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		stream.mu.Lock()
		got := len(stream.sent)
		stream.mu.Unlock()
		if got >= count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d sent messages", count)
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}
