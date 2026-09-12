//go:build linux

package testsecrets

import (
	"bytes"
	"errors"
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func deliveryFixture() (*runnerv1.JobSpecification, *runnerv1.GatewayMessage, time.Time) {
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	job := &runnerv1.JobSpecification{
		Lease:       &runnerv1.LeaseIdentity{LeaseId: "lease", ExecutionId: "execution", JobId: "job", ExpiresAt: timestamppb.New(now.Add(time.Minute))},
		Attempt:     &runnerv1.AttemptIdentity{AttemptId: "attempt", AttemptNumber: 1, ReleaseCandidateId: "candidate", MatrixEntryId: "matrix"},
		TestSecrets: []*runnerv1.TestSecretReference{{SecretId: "10000000-0000-0000-0000-000000000001", Name: "a", Version: 1}, {SecretId: "10000000-0000-0000-0000-000000000002", Name: "b", Version: 2}},
	}
	d := &runnerv1.TestSecretsDelivery{RequestMessageId: "request", Lease: proto.Clone(job.Lease).(*runnerv1.LeaseIdentity), Attempt: proto.Clone(job.Attempt).(*runnerv1.AttemptIdentity), ExpiresAt: timestamppb.New(now.Add(30 * time.Second))}
	for _, ref := range job.TestSecrets {
		d.Secrets = append(d.Secrets, &runnerv1.TestSecretValue{Reference: proto.Clone(ref).(*runnerv1.TestSecretReference), Value: []byte("synthetic\x00value")})
	}
	return job, &runnerv1.GatewayMessage{MessageId: "delivery", SentAt: timestamppb.New(now), Payload: &runnerv1.GatewayMessage_TestSecretsDelivery{TestSecretsDelivery: d}}, now
}

func TestTakeDeliveryTransfersThenClearsOwnedBuffers(t *testing.T) {
	job, m, now := deliveryFixture()
	d := m.GetTestSecretsDelivery()
	first := d.Secrets[0].Value
	inputs, expiry, err := TakeDelivery(job, "request", m, now)
	if err != nil || len(inputs) != 2 || inputs[0].Name != "a" || !bytes.Equal(inputs[0].Value, first) || !expiry.Equal(now.Add(30*time.Second)) {
		t.Fatal("valid delivery rejected")
	}
	for _, v := range d.Secrets {
		if v.Value != nil {
			t.Fatal("protobuf retained plaintext")
		}
	}
	ClearInputs(inputs)
	if inputs[0].Value != nil || !bytes.Equal(first, make([]byte, len(first))) {
		t.Fatal("owned plaintext not cleared")
	}
}

func TestTakeDeliveryRejectsAndClearsEveryValue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*runnerv1.JobSpecification, *runnerv1.GatewayMessage)
	}{
		{"request", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			m.GetTestSecretsDelivery().RequestMessageId = "other"
		}},
		{"lease", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			m.GetTestSecretsDelivery().Lease.LeaseId = "other"
		}},
		{"attempt", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			m.GetTestSecretsDelivery().Attempt.AttemptNumber++
		}},
		{"expired", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			m.GetTestSecretsDelivery().ExpiresAt = m.SentAt
		}},
		{"beyond lease", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			m.GetTestSecretsDelivery().ExpiresAt = timestamppb.New(j.Lease.ExpiresAt.AsTime().Add(time.Second))
		}},
		{"wrong version", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			m.GetTestSecretsDelivery().Secrets[0].Reference.Version++
		}},
		{"invalid utf8", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			m.GetTestSecretsDelivery().Secrets[0].Value[0] = 255
		}},
		{"duplicate", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			j.TestSecrets[1] = j.TestSecrets[0]
			m.GetTestSecretsDelivery().Secrets[1].Reference = j.TestSecrets[0]
		}},
		{"unknown", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			m.GetTestSecretsDelivery().Secrets[0].ProtoReflect().SetUnknown([]byte{0x78, 1})
		}},
		{"unsafe name", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			j.TestSecrets[0].Name = "../escape"
			m.GetTestSecretsDelivery().Secrets[0].Reference.Name = "../escape"
		}},
		{"oversize total", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			for _, v := range m.GetTestSecretsDelivery().Secrets {
				v.Value = bytes.Repeat([]byte("a"), MaximumBytes/2+1)
			}
		}},
		{"oversize frame", func(j *runnerv1.JobSpecification, m *runnerv1.GatewayMessage) {
			m.MessageId = string(bytes.Repeat([]byte("a"), MaximumDeliveryBytes))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j, m, now := deliveryFixture()
			tc.mutate(j, m)
			held := [][]byte{}
			for _, v := range m.GetTestSecretsDelivery().Secrets {
				held = append(held, v.Value)
			}
			inputs, _, err := TakeDelivery(j, "request", m, now)
			if !errors.Is(err, ErrUnavailable) || inputs != nil {
				ClearInputs(inputs)
				t.Fatal("malformed delivery accepted")
			}
			for _, v := range held {
				if !bytes.Equal(v, make([]byte, len(v))) {
					t.Fatal("failure retained plaintext")
				}
			}
		})
	}
}

func TestTakeDeliveryAcceptsExactAggregateBound(t *testing.T) {
	j, m, now := deliveryFixture()
	for _, v := range m.GetTestSecretsDelivery().Secrets {
		v.Value = bytes.Repeat([]byte("a"), MaximumBytes/2)
	}
	inputs, _, err := TakeDelivery(j, "request", m, now)
	defer ClearInputs(inputs)
	if err != nil || len(inputs) != 2 {
		t.Fatal("exact aggregate bound rejected")
	}
}
