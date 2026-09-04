package gatewayclient

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type duplicateCorrelationServerCodec struct{}

func (duplicateCorrelationServerCodec) Name() string { return "proto" }

func (duplicateCorrelationServerCodec) Marshal(value any) ([]byte, error) {
	if gateway, ok := value.(*runnerv1.GatewayMessage); ok && gateway.GetOffer() != nil {
		return duplicateCorrelationGatewayWire(gateway)
	}
	return proto.Marshal(value.(proto.Message))
}

func (duplicateCorrelationServerCodec) Unmarshal(data []byte, value any) error {
	return proto.Unmarshal(data, value.(proto.Message))
}

func duplicateCorrelationGatewayWire(message *runnerv1.GatewayMessage) ([]byte, error) {
	offer := message.GetOffer()
	job, err := proto.Marshal(offer.GetJob())
	if err != nil {
		return nil, err
	}
	correlation, err := proto.Marshal(offer.GetJob().GetJobCorrelation())
	if err != nil {
		return nil, err
	}
	job = protowire.AppendTag(job, 21, protowire.BytesType)
	job = protowire.AppendBytes(job, correlation)
	offerWire := protowire.AppendTag(nil, 1, protowire.BytesType)
	offerWire = protowire.AppendBytes(offerWire, job)
	expiresAt, err := proto.Marshal(offer.GetOfferExpiresAt())
	if err != nil {
		return nil, err
	}
	offerWire = protowire.AppendTag(offerWire, 2, protowire.BytesType)
	offerWire = protowire.AppendBytes(offerWire, expiresAt)
	gateway := protowire.AppendTag(nil, 1, protowire.BytesType)
	gateway = protowire.AppendString(gateway, message.GetMessageId())
	sentAt, err := proto.Marshal(message.GetSentAt())
	if err != nil {
		return nil, err
	}
	gateway = protowire.AppendTag(gateway, 2, protowire.BytesType)
	gateway = protowire.AppendBytes(gateway, sentAt)
	gateway = protowire.AppendTag(gateway, 11, protowire.BytesType)
	gateway = protowire.AppendBytes(gateway, offerWire)
	return gateway, nil
}

func TestConnectRawDecodeRejectsDuplicateCorrelationBeforePersistence(t *testing.T) {
	now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	offer := validLeaseOffer(now)
	offer.Job.JobCorrelation = validJobCorrelation(offer)
	wire, err := duplicateCorrelationGatewayWire(uniqueGatewayMessage(now, "duplicate-correlation", &runnerv1.GatewayMessage_Offer{Offer: offer}))
	if err != nil {
		t.Fatal(err)
	}
	if err := (strictProtocolCodec{}).Unmarshal(wire, new(runnerv1.GatewayMessage)); err == nil || !strings.Contains(err.Error(), "duplicate job correlation") {
		t.Fatalf("strict raw codec duplicate result = %v", err)
	}
	gateway := &testGateway{connect: func(stream grpc.BidiStreamingServer[runnerv1.RunnerMessage, runnerv1.GatewayMessage]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		authenticated := authenticatedMessage(now, platformScope())
		authenticated.GetAuthenticated().LeaseDuration = durationpb.New(10 * time.Minute)
		if err := stream.Send(authenticated); err != nil {
			return err
		}
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(uniqueGatewayMessage(now, "duplicate-correlation", &runnerv1.GatewayMessage_Offer{Offer: offer})); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.ForceServerCodec(duplicateCorrelationServerCodec{}))
	runnerv1.RegisterRunnerGatewayServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	connection, err := grpc.NewClient("passthrough:///bufconn", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	client, err := NewWithWorker(validConfig(), runnerv1.NewRunnerGatewayClient(connection), &gatedWorker{preparing: make(chan struct{}), executed: make(chan struct{}), now: now})
	if err != nil {
		t.Fatal(err)
	}
	client.config.Resources = validOfferConfig().Resources
	client.now = func() time.Time { return now }
	err = client.Run(context.Background())
	if err == nil || status.Code(err) != codes.Internal || transient(err) {
		t.Fatalf("duplicate wire carrier result = %v", err)
	}
	state := client.journal.snapshot()
	if state.Active != nil || len(state.PendingMessage) != 0 || client.isWorkerRunning() {
		t.Fatalf("duplicate carrier crossed persistence/execution boundary: %#v", state)
	}
}

func TestCorrelationPersistsBeforeAcceptanceAndCannotBleedAcrossOffers(t *testing.T) {
	now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	config := validConfig()
	config.Resources = validOfferConfig().Resources
	client := newClient(config, nil)
	client.worker = &gatedWorker{preparing: make(chan struct{}), executed: make(chan struct{}), now: now}
	authenticated := authenticatedMessage(now, platformScope()).GetAuthenticated()
	authenticated.LeaseDuration = durationpb.New(10 * time.Minute)
	var sent []*runnerv1.RunnerMessage
	session := &clientSession{
		client:           client,
		authenticated:    authenticated,
		jobCorrelationV1: true,
		rootContext:      context.Background(),
		send: func(message *runnerv1.RunnerMessage) error {
			sent = append(sent, proto.Clone(message).(*runnerv1.RunnerMessage))
			return nil
		},
	}
	first := validLeaseOffer(now)
	first.Job.JobCorrelation = validJobCorrelation(first)
	envelope := uniqueGatewayMessage(now, "correlated-offer", &runnerv1.GatewayMessage_Offer{Offer: first})
	if err := session.handleOffer(envelope, now); err != nil {
		t.Fatal(err)
	}
	state := client.journal.snapshot()
	if state.Active == nil || len(state.PendingMessage) == 0 || len(sent) != 1 || sent[0].GetLeaseAccepted() == nil {
		t.Fatalf("acceptance was not durably queued: state=%#v sent=%#v", state, sent)
	}
	persisted := new(runnerv1.JobSpecification)
	if err := proto.Unmarshal(state.Active.Specification, persisted); err != nil || !proto.Equal(persisted.JobCorrelation, first.Job.JobCorrelation) {
		t.Fatalf("persisted correlation = %#v, %v", persisted.JobCorrelation, err)
	}
	if err := session.handleOffer(proto.Clone(envelope).(*runnerv1.GatewayMessage), now); err != nil {
		t.Fatalf("exact correlated re-offer failed: %v", err)
	}
	if len(sent) != 2 || !proto.Equal(sent[0], sent[1]) || !bytes.Equal(client.journal.snapshot().Active.Specification, state.Active.Specification) {
		t.Fatal("exact correlated re-offer was not replayed byte-for-byte")
	}

	changed := proto.Clone(first).(*runnerv1.LeaseOffer)
	changed.Job.JobCorrelation.ProjectId = "70000000-0000-4000-8000-000000000002"
	if err := session.handleOffer(uniqueGatewayMessage(now, "changed-retry", &runnerv1.GatewayMessage_Offer{Offer: changed}), now); err == nil || transient(err) {
		t.Fatalf("changed correlation retry error = %v, want permanent conflict", err)
	}
	if !bytes.Equal(client.journal.snapshot().Active.Specification, state.Active.Specification) || len(sent) != 2 {
		t.Fatal("changed correlation retry mutated or acknowledged durable state")
	}

	if err := client.journal.update(func(state *journalState) error { state.PendingMessage = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	second := validLeaseOffer(now)
	second.Job.Lease.LeaseId = "10000000-0000-0000-0000-000000000002"
	second.Job.Lease.JobId = "20000000-0000-0000-0000-000000000002"
	second.Job.Lease.ExecutionId = second.Job.Lease.JobId
	second.Job.Attempt.AttemptId = "30000000-0000-0000-0000-000000000002"
	second.Job.Attempt.ReleaseCandidateId = "40000000-0000-0000-0000-000000000002"
	second.Job.Attempt.MatrixEntryId = "50000000-0000-0000-0000-000000000002"
	second.Job.JobCorrelation = validJobCorrelation(second)
	second.Job.JobCorrelation.OrganizationId = "60000000-0000-4000-8000-000000000002"
	second.Job.JobCorrelation.ProjectId = "70000000-0000-4000-8000-000000000002"
	if err := session.handleOffer(uniqueGatewayMessage(now, "other-tenant-offer", &runnerv1.GatewayMessage_Offer{Offer: second}), now); err != nil {
		t.Fatal(err)
	}
	current := client.journal.snapshot()
	if !bytes.Equal(current.Active.Specification, state.Active.Specification) || len(sent) != 3 || sent[2].GetLeaseRejected() == nil || sent[2].GetLeaseRejected().GetReason() != runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_AT_CAPACITY {
		t.Fatalf("concurrent tenant isolation state=%#v sent=%#v", current, sent)
	}
}

func TestJobCorrelationNegotiationFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	config := validOfferConfig()

	legacy := validLeaseOffer(now)
	if rejection := validateOffer(legacy, config, now, 10*time.Minute, false); rejection != nil {
		t.Fatalf("legacy carrier-free offer rejected: %#v", rejection)
	}
	legacy.Job.JobCorrelation = validJobCorrelation(legacy)
	if rejection := validateOffer(legacy, config, now, 10*time.Minute, false); rejection == nil || rejection.Code != "unexpected_job_correlation" {
		t.Fatalf("unadvertised carrier rejection = %#v", rejection)
	}

	missing := validLeaseOffer(now)
	if rejection := validateOffer(missing, config, now, 10*time.Minute, true); rejection == nil || rejection.Code != "missing_job_correlation" {
		t.Fatalf("missing negotiated carrier rejection = %#v", rejection)
	}
	valid := validLeaseOffer(now)
	valid.Job.JobCorrelation = validJobCorrelation(valid)
	if rejection := validateOffer(valid, config, now, 10*time.Minute, true); rejection != nil {
		t.Fatalf("valid negotiated carrier rejected: %#v", rejection)
	}
}

func TestJobCorrelationCanonicalBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*runnerv1.JobSpecification)
	}{
		{name: "uppercase trace", mutate: func(job *runnerv1.JobSpecification) {
			job.JobCorrelation.Traceparent = "00-0123456789abcdef0123456789abcdeF-0123456789abcdef-01"
		}},
		{name: "zero trace", mutate: func(job *runnerv1.JobSpecification) {
			job.JobCorrelation.Traceparent = "00-00000000000000000000000000000000-0123456789abcdef-01"
		}},
		{name: "zero parent", mutate: func(job *runnerv1.JobSpecification) {
			job.JobCorrelation.Traceparent = "00-0123456789abcdef0123456789abcdef-0000000000000000-01"
		}},
		{name: "reserved flags", mutate: func(job *runnerv1.JobSpecification) {
			job.JobCorrelation.Traceparent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-02"
		}},
		{name: "uppercase organization", mutate: func(job *runnerv1.JobSpecification) {
			job.JobCorrelation.OrganizationId = "60000000-0000-4000-8000-00000000000A"
		}},
		{name: "zero organization", mutate: func(job *runnerv1.JobSpecification) { job.JobCorrelation.OrganizationId = zeroUUID }},
		{name: "invalid project", mutate: func(job *runnerv1.JobSpecification) { job.JobCorrelation.ProjectId = "project" }},
		{name: "wrong workflow prefix", mutate: func(job *runnerv1.JobSpecification) {
			job.JobCorrelation.WorkflowId = "workflow/" + job.Attempt.ReleaseCandidateId
		}},
		{name: "wrong candidate", mutate: func(job *runnerv1.JobSpecification) {
			job.JobCorrelation.WorkflowId = jobCorrelationWorkflowPrefix + "40000000-0000-0000-0000-000000000002"
		}},
		{name: "unknown carrier field", mutate: func(job *runnerv1.JobSpecification) { job.JobCorrelation.ProtoReflect().SetUnknown([]byte{0x28, 0x01}) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			offer := validLeaseOffer(now)
			offer.Job.JobCorrelation = validJobCorrelation(offer)
			test.mutate(offer.Job)
			first := validateOffer(offer, validOfferConfig(), now, 10*time.Minute, true)
			second := validateOffer(offer, validOfferConfig(), now, 10*time.Minute, true)
			if first == nil || second == nil || first.Code != "invalid_job_correlation" || *first != *second {
				t.Fatalf("stable correlation rejection = %#v / %#v", first, second)
			}
		})
	}
}

func TestJobCorrelationDoesNotReplaceAuthorizationScope(t *testing.T) {
	now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	config := validOfferConfig()
	config.ExpectedScope = ExpectedScope{Kind: ScopeOrganization, OrganizationID: "60000000-0000-4000-8000-000000000001"}
	offer := validLeaseOffer(now)
	offer.Job.OrganizationScope = organizationScope(config.ExpectedScope.OrganizationID)
	offer.Job.JobCorrelation = validJobCorrelation(offer)
	if rejection := validateOffer(offer, config, now, 10*time.Minute, true); rejection != nil {
		t.Fatalf("matching scope/correlation rejected: %#v", rejection)
	}
	offer.Job.OrganizationScope = organizationScope("60000000-0000-4000-8000-000000000002")
	if rejection := validateOffer(offer, config, now, 10*time.Minute, true); rejection == nil || rejection.Code != "scope_mismatch" {
		t.Fatalf("authorization scope was not authoritative: %#v", rejection)
	}
	offer.Job.OrganizationScope = organizationScope(config.ExpectedScope.OrganizationID)
	offer.Job.JobCorrelation.OrganizationId = "60000000-0000-4000-8000-000000000002"
	if rejection := validateOffer(offer, config, now, 10*time.Minute, true); rejection == nil || rejection.Code != "job_correlation_scope_mismatch" {
		t.Fatalf("correlation tenant conflict rejection = %#v", rejection)
	}
}

func TestAdvertisedFeaturesAreUniqueAndKnown(t *testing.T) {
	features := newClient(validConfig(), nil).capabilities().GetFeatures()
	if err := validateAdvertisedFeatures(features); err != nil {
		t.Fatal(err)
	}
	correlationCount := 0
	restartRecoveryCount := 0
	for _, feature := range features {
		if feature == runnerv1.ProtocolFeature_PROTOCOL_FEATURE_JOB_CORRELATION_V1 {
			correlationCount++
		}
		if feature == runnerv1.ProtocolFeature_PROTOCOL_FEATURE_RESTART_UPLOAD_RECOVERY {
			restartRecoveryCount++
		}
	}
	if correlationCount != 1 || restartRecoveryCount != 1 {
		t.Fatalf("feature counts: correlation=%d restart-recovery=%d in %v", correlationCount, restartRecoveryCount, features)
	}
	if err := validateAdvertisedFeatures(append(features, runnerv1.ProtocolFeature_PROTOCOL_FEATURE_JOB_CORRELATION_V1)); err == nil {
		t.Fatal("duplicate job correlation feature accepted")
	}
	if err := validateAdvertisedFeatures(append(features, runnerv1.ProtocolFeature_PROTOCOL_FEATURE_RESTART_UPLOAD_RECOVERY)); err == nil {
		t.Fatal("duplicate restart upload recovery feature accepted")
	}
	if err := validateAdvertisedFeatures(append(features, runnerv1.ProtocolFeature(127))); err == nil {
		t.Fatal("unknown protocol feature accepted")
	}
}

func TestJournalPreservesCorrelationExactlyAndAcceptsLegacyRecovery(t *testing.T) {
	now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	path := t.TempDir() + "/journal.json"
	journal, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	offer := validLeaseOffer(now)
	offer.Job.JobCorrelation = validJobCorrelation(offer)
	specification, err := proto.MarshalOptions{Deterministic: true}.Marshal(offer.Job)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.update(func(state *journalState) error {
		state.Active = &journalJob{Specification: specification, OfferMessageID: "offer-1", OfferDigest: bytes.Repeat([]byte{1}, 32), JobCorrelationV1: true, Phase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED, ExpiresAt: offer.Job.Lease.ExpiresAt.AsTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reopened, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reopened.snapshot().Active.Specification, specification) {
		t.Fatal("correlation-bearing specification changed across journal restart")
	}
	persisted := new(runnerv1.JobSpecification)
	if err := proto.Unmarshal(reopened.snapshot().Active.Specification, persisted); err != nil || !proto.Equal(persisted.JobCorrelation, offer.Job.JobCorrelation) {
		t.Fatalf("persisted correlation = %#v, %v", persisted.JobCorrelation, err)
	}

	legacy := validLeaseOffer(now)
	legacySpecification, err := proto.MarshalOptions{Deterministic: true}.Marshal(legacy.Job)
	if err != nil {
		t.Fatal(err)
	}
	state := journalState{SchemaVersion: journalSchemaVersion, Active: &journalJob{Specification: legacySpecification, OfferMessageID: "legacy-offer", OfferDigest: bytes.Repeat([]byte{2}, 32), Phase: runnerv1.JobPhase_JOB_PHASE_ACCEPTED, ExpiresAt: legacy.Job.Lease.ExpiresAt.AsTime()}}
	if err := validateJournalState(state); err != nil {
		t.Fatalf("legacy carrier-free recovery rejected: %v", err)
	}
	state.Active.Specification = specification
	if err := validateJournalState(state); err == nil {
		t.Fatal("unnegotiated correlation-bearing journal was accepted")
	}
}
