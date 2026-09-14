package networkpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func authorityFixture(t *testing.T) (*Authority, *p.JobSpecification, *p.LeaseReconciliation, []p.ProtocolFeature, time.Time, time.Time) {
	t.Helper()
	raw, err := os.ReadFile("testdata/authority-v2-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != "dd0ebd7347d3b8e4a28b3b22a24618d0c40ee208c955a665a21325d3825096af" {
		t.Fatal("released authority vectors changed")
	}
	var vector struct {
		CurrentWireHex string
		Context        struct {
			Now, CredentialExpiresAt    time.Time
			Features                    []p.ProtocolFeature
			Lease, Attempt, Observation json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	lease, attempt, observation := new(p.LeaseIdentity), new(p.AttemptIdentity), new(p.NetworkAuthorityV2)
	for _, value := range []struct {
		raw     []byte
		message proto.Message
	}{{vector.Context.Lease, lease}, {vector.Context.Attempt, attempt}, {vector.Context.Observation, observation}} {
		if err := protojson.Unmarshal(value.raw, value.message); err != nil {
			t.Fatal(err)
		}
	}
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(observation)
	if err != nil || hex.EncodeToString(wire) != vector.CurrentWireHex {
		t.Fatal("released authority wire changed", err)
	}
	policy, encoded := releasedEffectiveV2(t)
	digest := sha256.Sum256(encoded)
	job := &p.JobSpecification{Lease: lease, Attempt: attempt, EffectivePolicy: policy, Hashes: &p.JobHashes{Policy: &p.Digest{Algorithm: p.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest[:]}}}
	authority, err := NewAuthority(job)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation := &p.LeaseReconciliation{Lease: proto.Clone(lease).(*p.LeaseIdentity), Attempt: proto.Clone(attempt).(*p.AttemptIdentity), Status: p.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: p.JobPhase_JOB_PHASE_RUNNING, Disposition: p.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE, NetworkAuthorityV2: observation}
	return authority, job, reconciliation, vector.Context.Features, vector.Context.CredentialExpiresAt, vector.Context.Now
}

func TestAuthorityReleasedIdentityAndStaleDisposition(t *testing.T) {
	a, job, receipt, features, credential, now := authorityFixture(t)
	before := proto.Clone(receipt)
	job.Lease.JobId = "changed"
	job.Hashes.Policy.Value[0]++
	job.EffectivePolicy.NetworkV2.MaximumConnections++
	if err := a.Reconcile(receipt, features, credential, now); err != nil {
		t.Fatal("STALE incorrectly revoked fresh authority", err)
	}
	deadline, err := a.Deadline(now)
	if err != nil || !deadline.Equal(receipt.NetworkAuthorityV2.ExpiresAt.AsTime()) || !proto.Equal(before, receipt) {
		t.Fatal("identity or input mutation", err)
	}
	if _, err := NewAuthority(job); err == nil {
		t.Fatal("mutated job identity admitted")
	}
	if _, err := NewAuthority(nil); err == nil {
		t.Fatal("nil authority accepted")
	}
	if err := (&Authority{}).Reconcile(receipt, features, credential, now); err == nil {
		t.Fatal("zero authority accepted")
	}
}

func TestAuthorityMalformedOrUnnegotiatedMetadataWithdraws(t *testing.T) {
	for name, change := range map[string]func(*Authority, *p.LeaseReconciliation, *[]p.ProtocolFeature, *time.Time, time.Time){
		"missing": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.NetworkAuthorityV2 = nil
		},
		"unknown state": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.NetworkAuthorityV2.State = 99
		},
		"unspecified state": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.NetworkAuthorityV2.State = 0
		},
		"wrong digest": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.NetworkAuthorityV2.Policy.Value[0]++
		},
		"short digest": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.NetworkAuthorityV2.Policy.Value = r.NetworkAuthorityV2.Policy.Value[:31]
		},
		"unknown algorithm": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.NetworkAuthorityV2.Policy.Algorithm = 0
		},
		"missing digest": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.NetworkAuthorityV2.Policy = nil
		},
		"unknown metadata": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.NetworkAuthorityV2.ProtoReflect().SetUnknown([]byte{0x98, 6, 1})
		},
		"unknown digest field": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.NetworkAuthorityV2.Policy.ProtoReflect().SetUnknown([]byte{0x98, 6, 1})
		},
		"missing checked": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.NetworkAuthorityV2.CheckedAt = nil
		},
		"future checked": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, now time.Time) {
			r.NetworkAuthorityV2.CheckedAt = timestamppb.New(now.Add(5*time.Second + time.Nanosecond))
		},
		"missing expiry": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.NetworkAuthorityV2.ExpiresAt = nil
		},
		"expired": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, now time.Time) {
			r.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now)
		},
		"expiry before check": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, now time.Time) {
			r.NetworkAuthorityV2.CheckedAt = timestamppb.New(now.Add(4 * time.Second))
			r.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(3 * time.Second))
		},
		"over sixty seconds": func(a *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, now time.Time) {
			a.lease.ExpiresAt = timestamppb.New(now.Add(time.Hour))
			r.NetworkAuthorityV2.ExpiresAt = timestamppb.New(r.NetworkAuthorityV2.CheckedAt.AsTime().Add(time.Minute + time.Nanosecond))
		},
		"lease bound": func(a *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, now time.Time) {
			a.lease.ExpiresAt = timestamppb.New(now.Add(time.Second))
			r.Lease.ExpiresAt = timestamppb.New(now.Add(time.Second))
		},
		"credential bound": func(_ *Authority, _ *p.LeaseReconciliation, _ *[]p.ProtocolFeature, expiry *time.Time, now time.Time) {
			*expiry = now.Add(time.Second)
		},
		"wrong lease": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.Lease.LeaseId = "20000000-0000-4000-8000-000000000001"
		},
		"wrong job": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.Lease.JobId = "20000000-0000-4000-8000-000000000001"
		},
		"wrong execution": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.Lease.ExecutionId = "20000000-0000-4000-8000-000000000001"
		},
		"wrong attempt": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.Attempt.AttemptId = "20000000-0000-4000-8000-000000000001"
		},
		"wrong candidate": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.Attempt.ReleaseCandidateId = "20000000-0000-4000-8000-000000000001"
		},
		"wrong matrix": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.Attempt.MatrixEntryId = "20000000-0000-4000-8000-000000000001"
		},
		"wrong attempt number": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.Attempt.AttemptNumber++
		},
		"unknown status": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.Status = 99
		},
		"unnegotiated": func(_ *Authority, _ *p.LeaseReconciliation, f *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			*f = (*f)[:3]
		},
		"missing dependency": func(_ *Authority, _ *p.LeaseReconciliation, f *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			*f = []p.ProtocolFeature{1, 9, 10}
		},
		"duplicate feature": func(_ *Authority, _ *p.LeaseReconciliation, f *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			*f = append(*f, 10)
		},
		"unknown feature": func(_ *Authority, _ *p.LeaseReconciliation, f *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			*f = append(*f, 11)
		},
		"unexpected offered": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.Status = p.LeaseStatus_LEASE_STATUS_OFFERED
		},
		"unexpected cancelling": func(_ *Authority, r *p.LeaseReconciliation, _ *[]p.ProtocolFeature, _ *time.Time, _ time.Time) {
			r.Phase = p.JobPhase_JOB_PHASE_CANCELLING
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, _, receipt, features, credential, now := authorityFixture(t)
			good := proto.Clone(receipt).(*p.LeaseReconciliation)
			change(a, receipt, &features, &credential, now)
			if err := a.Reconcile(receipt, features, credential, now); err == nil {
				t.Fatal("invalid authority admitted")
			}
			_ = a.Reconcile(good, []p.ProtocolFeature{1, 3, 9, 10}, now.Add(time.Hour), now)
			if _, err := a.Deadline(now); err == nil {
				t.Fatal("invalid authority could resume")
			}
		})
	}
}

func TestAuthorityOrderingAndOldExpiredLeaseReceipt(t *testing.T) {
	a, _, receipt, features, credential, now := authorityFixture(t)
	if err := a.Reconcile(receipt, features, credential, now); err != nil {
		t.Fatal(err)
	}
	original := proto.Clone(receipt).(*p.LeaseReconciliation)
	// A newer lease is independently acknowledged with an older positive check.
	receipt.Lease.ExpiresAt = timestamppb.New(now.Add(3 * time.Minute))
	receipt.NetworkAuthorityV2.CheckedAt = timestamppb.New(now.Add(-6 * time.Second))
	receipt.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(29 * time.Second))
	if err := a.Reconcile(receipt, features, credential, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.Deadline(now); !got.Equal(original.NetworkAuthorityV2.ExpiresAt.AsTime()) {
		t.Fatal("older check changed deadline")
	}
	// Later, an old already-expired lease receipt carries a fresh observation
	// bounded by the renewal that has already been independently acknowledged.
	original.Lease.ExpiresAt = timestamppb.New(now.Add(-time.Second))
	original.NetworkAuthorityV2.CheckedAt = timestamppb.New(now.Add(time.Second))
	original.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(60 * time.Second))
	if err := a.Reconcile(original, features, credential, now.Add(time.Second)); err != nil {
		t.Fatal("old receipt invalidated settled renewal", err)
	}
	// Newer authority may legitimately shorten the still-live deadline.
	original.NetworkAuthorityV2.CheckedAt = timestamppb.New(now.Add(2 * time.Second))
	original.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(20 * time.Second))
	if err := a.Reconcile(original, features, credential, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.Deadline(now); !got.Equal(now.Add(20 * time.Second)) {
		t.Fatal("shorter authority ignored")
	}
	original.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(21 * time.Second))
	if err := a.Reconcile(original, features, credential, now.Add(2*time.Second)); err == nil {
		t.Fatal("equal check changed deadline")
	}
}

func TestAuthorityWithdrawalExpiryAndNoneAreIrreversible(t *testing.T) {
	for _, kind := range []string{"explicit", "expiry", "terminal", "cancelling", "none", "offered"} {
		t.Run(kind, func(t *testing.T) {
			a, _, receipt, features, credential, now := authorityFixture(t)
			good := proto.Clone(receipt).(*p.LeaseReconciliation)
			if kind != "none" && kind != "offered" {
				if err := a.Reconcile(receipt, features, credential, now); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "explicit":
				receipt.NetworkAuthorityV2.State = p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_WITHDRAWN
				receipt.NetworkAuthorityV2.ExpiresAt = nil
			case "expiry":
				now = receipt.NetworkAuthorityV2.ExpiresAt.AsTime()
				receipt.NetworkAuthorityV2.CheckedAt = timestamppb.New(now)
				receipt.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(5 * time.Second))
			case "terminal":
				receipt.Status = p.LeaseStatus_LEASE_STATUS_COMPLETED
				receipt.NetworkAuthorityV2 = nil
			case "cancelling":
				receipt.Phase = p.JobPhase_JOB_PHASE_CANCELLING
				receipt.NetworkAuthorityV2 = nil
			case "none":
				a.policy.Mode = p.NetworkMode_NETWORK_MODE_NONE
				receipt.NetworkAuthorityV2 = nil
			case "offered":
				receipt.Status = p.LeaseStatus_LEASE_STATUS_OFFERED
				receipt.NetworkAuthorityV2 = nil
			}
			if err := a.Reconcile(receipt, features, credential, now); err != nil {
				t.Fatal(err)
			}
			if _, err := a.Deadline(now); err == nil {
				t.Fatal("non-current authority granted")
			}
			if kind == "none" || kind == "offered" {
				return
			}
			good.NetworkAuthorityV2.CheckedAt = timestamppb.New(now)
			good.NetworkAuthorityV2.ExpiresAt = timestamppb.New(now.Add(5 * time.Second))
			_ = a.Reconcile(good, features, credential, now)
			if _, err := a.Deadline(now); err == nil {
				t.Fatal("withdrawn attempt resumed")
			}
		})
	}
}

func authorityBindings(a *Authority, now time.Time) []Binding {
	byHost := map[string]*Binding{}
	var result []Binding
	for _, grant := range a.policy.Permissions {
		binding := byHost[grant.Hostname]
		if binding == nil {
			binding = &Binding{job: a.lease.JobId, hostname: grant.Hostname, addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}, limits: Limits{uint64(a.policy.MaximumConnections), uint64(a.policy.MaximumBytesPerSecond)}, issued: now.Add(-time.Second), expires: now.Add(2 * time.Minute)}
			byHost[grant.Hostname] = binding
		}
		transport := "tcp"
		if grant.Transport == p.NetworkTransportV2_NETWORK_TRANSPORT_V2_UDP {
			transport = "udp"
		}
		binding.permissions = append(binding.permissions, Permission{grant.Hostname, uint16(grant.Port), transport})
	}
	for _, binding := range byHost {
		result = append(result, *binding)
	}
	return result
}

func TestAuthorityConstrainsOnlyOriginalBindings(t *testing.T) {
	a, _, receipt, features, credential, now := authorityFixture(t)
	if err := a.Reconcile(receipt, features, credential, now); err != nil {
		t.Fatal(err)
	}
	bindings := authorityBindings(a, now)
	bounded, err := a.ConstrainBindings(bindings, now)
	if err != nil || len(bounded) != len(bindings) {
		t.Fatal(err)
	}
	for i := range bounded {
		if !bounded[i].expires.Equal(receipt.NetworkAuthorityV2.ExpiresAt.AsTime()) || !bindings[i].expires.Equal(now.Add(2*time.Minute)) {
			t.Fatal("binding deadline mismatch")
		}
	}
	bindings[0].addresses[0] = netip.MustParseAddr("1.1.1.1")
	if bounded[0].addresses[0] == bindings[0].addresses[0] {
		t.Fatal("binding address alias")
	}
	for name, change := range map[string]func([]Binding) []Binding{
		"missing":      func(b []Binding) []Binding { return b[:len(b)-1] },
		"wrong job":    func(b []Binding) []Binding { b[0].job = "20000000-0000-4000-8000-000000000001"; return b },
		"changed port": func(b []Binding) []Binding { b[0].permissions[0].Port++; return b },
		"changed cap":  func(b []Binding) []Binding { b[0].limits.Connections++; return b },
		"expired":      func(b []Binding) []Binding { b[0].expires = now; return b },
		"duplicate":    func(b []Binding) []Binding { return append(b, b[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			a, _, r, f, c, n := authorityFixture(t)
			if err := a.Reconcile(r, f, c, n); err != nil {
				t.Fatal(err)
			}
			if bounded, err := a.ConstrainBindings(change(authorityBindings(a, n)), n); err == nil || bounded != nil {
				t.Fatal("changed binding accepted")
			}
			if _, err := a.Deadline(n); err == nil {
				t.Fatal("failed binding did not withdraw")
			}
		})
	}
}

func TestAuthorityConcurrentWithdrawalCannotResume(t *testing.T) {
	a, _, receipt, features, credential, now := authorityFixture(t)
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 100 {
				_ = a.Reconcile(receipt, features, credential, now)
				_, _ = a.Deadline(now)
			}
		}()
	}
	a.Withdraw()
	group.Wait()
	if _, err := a.Deadline(now); err == nil {
		t.Fatal("concurrent withdrawal revived")
	}
	if !bytes.Equal(a.digest[:], receipt.NetworkAuthorityV2.Policy.Value) {
		t.Fatal("immutable digest mutated")
	}
}
