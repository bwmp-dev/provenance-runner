package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func unsolicitedSecretFixture() (*runnerv1.GatewayMessage, []byte) {
	value := []byte("synthetic-do-not-hash-or-log")
	return &runnerv1.GatewayMessage{Payload: &runnerv1.GatewayMessage_TestSecretsDelivery{
		TestSecretsDelivery: &runnerv1.TestSecretsDelivery{Secrets: []*runnerv1.TestSecretValue{nil, {Value: value}}},
	}}, value
}

func TestUnsolicitedSecretsNeverEnterReplayHashing(t *testing.T) {
	for _, boundary := range []string{"remember", "duplicate", "handler"} {
		t.Run(boundary, func(t *testing.T) {
			message, owned := unsolicitedSecretFixture()
			session := &clientSession{seen: make(map[string][sha256.Size]byte)}
			var err error
			switch boundary {
			case "remember":
				err = session.rememberGatewayMessage(message)
			case "duplicate":
				_, err = session.gatewayMessageDuplicate(message)
			case "handler":
				err = session.handleGatewayMessage(message, time.Now())
			}
			if err == nil || strings.Contains(err.Error(), "synthetic") {
				t.Fatal("delivery refusal leaked or was absent")
			}
			if len(session.seen) != 0 || len(session.seenOrder) != 0 {
				t.Fatal("delivery entered replay state")
			}
			if !bytes.Equal(owned, make([]byte, len(owned))) || message.GetTestSecretsDelivery().Secrets[1].Value != nil {
				t.Fatal("owned delivery buffers retained")
			}
		})
	}
	clearTestSecretDelivery(nil)
}

func TestWireRefusesSecretCarriersBeforeDecoding(t *testing.T) {
	message, _ := unsolicitedSecretFixture()
	wire, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	// A later oneof payload must not hide a secret allocation from rejection.
	overridden := protowire.AppendTag(bytes.Clone(wire), 10, protowire.BytesType)
	overridden = protowire.AppendBytes(overridden, nil)
	for _, data := range [][]byte{wire, overridden} {
		decoded := new(runnerv1.GatewayMessage)
		if err := (strictProtocolCodec{}).Unmarshal(data, decoded); err == nil || strings.Contains(err.Error(), "synthetic") {
			t.Fatal("wire delivery was not safely refused")
		}
		if decoded.GetPayload() != nil {
			t.Fatal("delivery decoded before rejection")
		}
	}
}

func TestAuthenticatedStreamRefusesUnsolicitedSecrets(t *testing.T) {
	now := time.Now().UTC()
	server := &testGateway{connect: func(stream grpc.BidiStreamingServer[runnerv1.RunnerMessage, runnerv1.GatewayMessage]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(authenticatedMessage(now, platformScope())); err != nil {
			return err
		}
		for range 2 {
			if _, err := stream.Recv(); err != nil {
				return err
			}
		}
		message, _ := unsolicitedSecretFixture()
		return stream.Send(message)
	}}
	client, closeConnection := bufconnClient(t, server)
	defer closeConnection()
	client.now = func() time.Time { return now }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	established, err := client.runSession(ctx)
	if !established || err == nil || !strings.Contains(err.Error(), "unsolicited test-secret delivery") || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("unexpected stream refusal: established=%v err=%v", established, err)
	}
	state := client.journal.snapshot()
	if state.Active != nil || len(state.PendingMessage) != 0 {
		t.Fatal("unsolicited delivery changed durable job state")
	}
}

func TestHandshakeAndReceiveErrorClearOwnedSecrets(t *testing.T) {
	for _, receiveErr := range []error{nil, errors.New("synthetic transport failure")} {
		message, owned := unsolicitedSecretFixture()
		stream := newScriptedStream(context.Background())
		stream.receives <- receiveResult{message: message, err: receiveErr}
		client := newClient(validConfig(), &scriptedConnector{results: []connectResult{{stream: stream}}})
		defer client.Close()
		if established, err := client.runSession(context.Background()); established || err == nil {
			t.Fatal("secret handshake accepted")
		}
		if !bytes.Equal(owned, make([]byte, len(owned))) {
			t.Fatal("handshake/error retained secret buffer")
		}
	}
}

type cancelSecretStream struct {
	*scriptedStream
	cancel  context.CancelFunc
	message *runnerv1.GatewayMessage
}

func (s *cancelSecretStream) Recv() (*runnerv1.GatewayMessage, error) {
	if s.message != nil {
		message := s.message
		s.message = nil
		s.cancel()
		return message, nil
	}
	return s.scriptedStream.Recv()
}

func TestCancelledReceiverClearsUndeliveredSecrets(t *testing.T) {
	for range 20 {
		ctx, cancel := context.WithCancel(context.Background())
		message, owned := unsolicitedSecretFixture()
		stream := &cancelSecretStream{scriptedStream: newScriptedStream(ctx), cancel: cancel, message: message}
		client := newClient(validConfig(), &scriptedConnector{results: []connectResult{{stream: stream}}})
		_, err := client.runSession(ctx)
		cancel()
		_ = client.Close()
		if err == nil {
			t.Fatal("cancelled delivery accepted")
		}
		if !bytes.Equal(owned, make([]byte, len(owned))) {
			t.Fatal("cancelled receiver retained secret buffer")
		}
	}
}
