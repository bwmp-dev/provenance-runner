package networkpolicy

import (
	"bytes"
	"encoding/binary"
	"time"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maximumAuthorityUpdateBytes = 16 << 10

// AuthorityUpdate is authenticated only by its transport owner. Its receipt is
// not permission: the root authority supervisor must Reconcile it against the
// exact job and current time. No gateway token or object-transfer URI is carried.
type AuthorityUpdate struct {
	Reconciliation   *p.LeaseReconciliation
	Features         []p.ProtocolFeature
	CredentialExpiry time.Time
}

func projectedReconciliation(value *p.LeaseReconciliation) (*p.LeaseReconciliation, error) {
	if value == nil || proto.Size(value) > maximumAuthorityUpdateBytes-20 || !closedWireV2(value.ProtoReflect()) {
		return nil, ErrAuthority
	}
	copy := proto.Clone(value).(*p.LeaseReconciliation)
	if copy.CompleteLogUpload != nil {
		copy.CompleteLogUpload.Uri = ""
		copy.CompleteLogUpload.ExpiresAt = nil
	}
	return copy, nil
}

func EncodeAuthorityUpdate(value AuthorityUpdate) ([]byte, error) {
	negotiated, err := authorityFeatures(value.Features)
	if err != nil || !negotiated || value.CredentialExpiry.IsZero() || !timestamppb.New(value.CredentialExpiry).IsValid() {
		return nil, ErrAuthority
	}
	r, err := projectedReconciliation(value.Reconciliation)
	if err != nil {
		return nil, err
	}
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(r)
	if err != nil || len(raw) == 0 || len(raw) > maximumAuthorityUpdateBytes-20 {
		return nil, ErrAuthority
	}
	result := make([]byte, 20+len(raw))
	copy(result, "PVA1")
	var bits uint16
	for _, feature := range value.Features {
		bits |= 1 << uint(feature-1)
	}
	binary.BigEndian.PutUint16(result[4:6], bits)
	binary.BigEndian.PutUint64(result[8:16], uint64(value.CredentialExpiry.Unix()))
	binary.BigEndian.PutUint32(result[16:20], uint32(value.CredentialExpiry.Nanosecond()))
	copy(result[20:], raw)
	return result, nil
}

func DecodeAuthorityUpdate(raw []byte) (AuthorityUpdate, error) {
	fail := func() (AuthorityUpdate, error) { return AuthorityUpdate{}, ErrAuthority }
	if len(raw) <= 20 || len(raw) > maximumAuthorityUpdateBytes || string(raw[:4]) != "PVA1" || raw[6] != 0 || raw[7] != 0 {
		return fail()
	}
	bits := binary.BigEndian.Uint16(raw[4:6])
	if bits>>10 != 0 {
		return fail()
	}
	var features []p.ProtocolFeature
	for i := 0; i < 10; i++ {
		if bits&(1<<uint(i)) != 0 {
			features = append(features, p.ProtocolFeature(i+1))
		}
	}
	nanos := binary.BigEndian.Uint32(raw[16:20])
	if nanos >= 1e9 {
		return fail()
	}
	expiry := time.Unix(int64(binary.BigEndian.Uint64(raw[8:16])), int64(nanos)).UTC()
	r := new(p.LeaseReconciliation)
	if (proto.UnmarshalOptions{RecursionLimit: 64}).Unmarshal(raw[20:], r) != nil {
		return fail()
	}
	projected, err := projectedReconciliation(r)
	if err != nil || !proto.Equal(r, projected) {
		return fail()
	}
	value := AuthorityUpdate{r, features, expiry}
	canonical, err := EncodeAuthorityUpdate(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return fail()
	}
	return value, nil
}
