//go:build linux

package gvisor

import "testing"

func TestMeasuredSecretRecordsClosedProfile(t *testing.T) {
	r := measuredBundleRecord{}
	if !validMeasuredSecretRecord(r, false) || !validMeasuredSecretRecord(r, true) {
		t.Fatal("legacy record refused")
	}
	r.SecretParentIno = 1
	if validMeasuredSecretRecord(r, false) {
		t.Fatal("partial metadata accepted")
	}
	r.SecretBoot = "11111111-1111-1111-1111-111111111111"
	r.SecretParentDev = 1
	if !validMeasuredSecretRecord(r, false) || validMeasuredSecretRecord(r, true) {
		t.Fatal("intent/ownership confused")
	}
	r.SecretDev, r.SecretIno = 1, 2
	if validMeasuredSecretRecord(r, false) || !validMeasuredSecretRecord(r, true) {
		t.Fatal("owned profile confused")
	}
	r.SecretBoot = "00000000-0000-0000-0000-000000000000"
	if validMeasuredSecretRecord(r, true) {
		t.Fatal("zero boot accepted")
	}
	if measuredSecretParent(nil) {
		t.Fatal("nil parent accepted")
	}
	if _, err := OpenMeasuredBundleJournalWithSecrets(nil, nil, nil, nil); err == nil {
		t.Fatal("unprovisioned journal accepted")
	}
}
