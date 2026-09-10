package paper

import (
	"strconv"
	"strings"
)

const LegacyProbeVersion = "0.2.0"
const LegacyProbeSourceCommit = "18400bb4a47d28c1d95c3f4067603af3f3409d5e"
const LegacyProbeSHA256 = "141a535d495a3afd5f413cab04618e75421390f0e14acba0707d1573c5a8c96b"
const LegacyProbeSizeBytes = int64(480768)

func acceptedProbe(c Catalog) bool {
	if c.Probe.Filename != "paper-probe.jar" {
		return false
	}
	if c.ProbeVersion == LegacyProbeVersion && c.ProbeSourceCommit == LegacyProbeSourceCommit && c.Probe.SHA256 == LegacyProbeSHA256 && c.Probe.SizeBytes == LegacyProbeSizeBytes {
		return true
	}
	if c.ProbeVersion != AlphaProbeVersion || c.ProbeSourceCommit != AlphaProbeSourceCommit || c.Probe.SHA256 != AlphaProbeSHA256 || c.Probe.SizeBytes != AlphaProbeSizeBytes {
		return false
	}
	// Retain old modern catalogs, but never run Java 21/API 1.20.6 probe bytes
	// on a legacy server merely because the signature itself is valid.
	v := c.Paper.GameVersion
	if v == "1.21" || strings.HasPrefix(v, "1.21.") || strings.HasPrefix(v, "26.") {
		return true
	}
	if !strings.HasPrefix(v, "1.20.") {
		return false
	}
	patch, err := strconv.Atoi(strings.TrimPrefix(v, "1.20."))
	return err == nil && patch >= 6
}
