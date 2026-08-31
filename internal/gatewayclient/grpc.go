package gatewayclient

import (
	"context"
	"crypto/tls"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type generatedConnector struct {
	client runnerv1.RunnerGatewayClient
}

func (c *generatedConnector) connect(ctx context.Context) (gatewayStream, error) {
	return c.client.Connect(
		ctx,
		grpc.MaxCallRecvMsgSize(MaximumMessageBytes),
		grpc.MaxCallSendMsgSize(MaximumMessageBytes),
	)
}

func Dial(config Config) (*Client, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	connection, err := grpc.NewClient(
		config.GatewayAddress,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
		grpc.WithDisableRetry(),
		grpc.WithUserAgent("provenance-runner/"+config.RunnerVersion),
	)
	if err != nil {
		return nil, err
	}
	client, err := New(config, runnerv1.NewRunnerGatewayClient(connection))
	if err != nil {
		connection.Close()
		return nil, err
	}
	client.close = connection.Close
	return client, nil
}
