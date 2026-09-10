package paper

import "testing"

func TestLegacyProbeIdentityAndRollback(t *testing.T) {
	c := operatorFixture()
	if !acceptedProbe(c) {
		t.Fatal("original modern probe refused")
	}
	c.Paper.GameVersion = "1.8.8"
	if acceptedProbe(c) {
		t.Fatal("old probe accepted for legacy server")
	}
	c.Java.Version = "8.0.504+1"
	c.ProbeVersion, c.ProbeSourceCommit = LegacyProbeVersion, LegacyProbeSourceCommit
	c.Probe.SHA256, c.Probe.SizeBytes = LegacyProbeSHA256, LegacyProbeSizeBytes
	if err := ValidateOperatorCatalog(c, false); err != nil {
		t.Fatal(err)
	}
	c.ProbeSourceCommit = AlphaProbeSourceCommit
	if acceptedProbe(c) {
		t.Fatal("mixed probe identity accepted")
	}
}
