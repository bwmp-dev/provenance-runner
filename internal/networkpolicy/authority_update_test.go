package networkpolicy

import (
	"bytes"
	"encoding/binary"
	"testing"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthorityUpdateRemovesCapabilitiesWithoutChangingAuthority(t *testing.T) {
	a, _, receipt, features, expiry, now := authorityFixture(t)
	receipt.CompleteLogUpload = &p.ObjectUpload{Uri: "https://object.example/?synthetic-authority-upload", ExpiresAt: timestamppb.New(expiry), ObjectKey: "data/logs/bound.gz"}
	before := proto.Clone(receipt)
	raw, err := EncodeAuthorityUpdate(AuthorityUpdate{receipt, features, expiry})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("synthetic-authority-upload")) || !proto.Equal(before, receipt) {
		t.Fatal("authority update leaked or mutated source")
	}
	got, err := DecodeAuthorityUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.CredentialExpiry.Equal(expiry) || got.Reconciliation.CompleteLogUpload.Uri != "" || got.Reconciliation.CompleteLogUpload.ExpiresAt != nil || !proto.Equal(got.Reconciliation.NetworkAuthorityV2, receipt.NetworkAuthorityV2) {
		t.Fatal("authority identity/deadline changed")
	}
	if err := a.Reconcile(got.Reconciliation, got.Features, got.CredentialExpiry, now); err != nil {
		t.Fatal("projected authority refused", err)
	}
	raw[len(raw)-1] ^= 1
	if !proto.Equal(got.Reconciliation.NetworkAuthorityV2, receipt.NetworkAuthorityV2) {
		t.Fatal("mutable update escaped")
	}
}

func TestAuthorityUpdateRejectsMalformedEncoding(t *testing.T) {
	_, _, receipt, features, expiry, _ := authorityFixture(t)
	raw, err := EncodeAuthorityUpdate(AuthorityUpdate{receipt, features, expiry})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{"short": raw[:19], "truncated": raw[:len(raw)-1], "trailing": append(append([]byte(nil), raw...), 0)}
	for _, index := range []int{0, 6, 7} {
		bad := append([]byte(nil), raw...)
		bad[index] ^= 1
		cases[string(rune('a'+index))] = bad
	}
	bad := append([]byte(nil), raw...)
	binary.BigEndian.PutUint16(bad[4:6], 0xffff)
	cases["feature overflow"] = bad
	bad = append([]byte(nil), raw...)
	binary.BigEndian.PutUint32(bad[16:20], 1e9)
	cases["nanoseconds"] = bad
	receipt.CompleteLogUpload = &p.ObjectUpload{Uri: "https://object.example/?synthetic-credential"}
	encoded, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(receipt)
	cases["unprojected"] = append(append([]byte(nil), raw[:20]...), encoded...)
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := DecodeAuthorityUpdate(raw); err == nil || got.Reconciliation != nil {
				t.Fatal("invalid authority update admitted")
			}
		})
	}
	if _, err := EncodeAuthorityUpdate(AuthorityUpdate{receipt, append(features, features[0]), expiry}); err == nil {
		t.Fatal("duplicate feature accepted")
	}
}
