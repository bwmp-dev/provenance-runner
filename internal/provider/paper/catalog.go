package paper

import "strconv"

const (
	Paper1206EnvironmentID = "paper-1.20.6-151-linux-amd64-temurin-21.0.8+9"
	Paper1214EnvironmentID = "paper-1.21.4-232-linux-amd64-temurin-21.0.8+9"
	AlphaEnvironmentID     = "paper-1.21.8-60-linux-amd64-temurin-21.0.8+9"
	AlphaProbeVersion      = "0.1.0"
	AlphaProbeSourceCommit = "f82dcbf8244354059731ba533f73909ed5528bbd"
	AlphaProbeSHA256       = "040062e4ea15fdffe3c37e4402b978527dd4864870edefe2c662209e12d63868"
	AlphaProbeSizeBytes    = int64(478_853)
	DownloadUserAgent      = "Provenance-Runner/0.1.0 (https://github.com/bwmp-dev/provenance-runner)"
)

type ArtifactPin struct {
	URI       string `json:"uri"`
	SHA256    string `json:"sha256"`
	Filename  string `json:"filename"`
	SizeBytes int64  `json:"sizeBytes"`
}

type PaperPin struct {
	GameVersion string      `json:"gameVersion"`
	Build       uint32      `json:"build"`
	Artifact    ArtifactPin `json:"artifact"`
}

type JavaPin struct {
	Distribution         string      `json:"distribution"`
	Version              string      `json:"version"`
	OS                   string      `json:"os"`
	Architecture         string      `json:"architecture"`
	ArchiveRoot          string      `json:"archiveRoot"`
	Artifact             ArtifactPin `json:"artifact"`
	MaximumExpandedBytes int64       `json:"maximumExpandedBytes"`
}

type ArchivePin struct {
	Artifact             ArtifactPin `json:"artifact"`
	MaximumExpandedBytes int64       `json:"maximumExpandedBytes"`
}

type Catalog struct {
	EnvironmentID     string      `json:"environmentId"`
	Paper             PaperPin    `json:"paper"`
	Java              JavaPin     `json:"java"`
	ProbeVersion      string      `json:"probeVersion"`
	ProbeSourceCommit string      `json:"probeSourceCommit"`
	Probe             ArtifactPin `json:"probe"`
	PreparedRuntime   ArchivePin  `json:"preparedRuntime"`
}

func AlphaCatalog() Catalog {
	return catalog(
		AlphaEnvironmentID,
		"1.21.8",
		60,
		"8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e",
		52_811_717,
	)
}

// AlphaCatalogs returns the complete, bounded Paper environment matrix used by
// the alpha control plane. PreparedRuntime remains operator-supplied for every
// entry and must be populated before a catalog can construct a Provider.
func AlphaCatalogs() []Catalog {
	return []Catalog{
		catalog(
			Paper1206EnvironmentID,
			"1.20.6",
			151,
			"4b011f5adb5f6c72007686a223174fce82f31aeb4b34faf4652abc840b47e640",
			45_826_876,
		),
		catalog(
			Paper1214EnvironmentID,
			"1.21.4",
			232,
			"5ee4f542f628a14c644410b08c94ea42e772ef4d29fe92973636b6813d4eaffc",
			51_437_498,
		),
		AlphaCatalog(),
	}
}

// CatalogForEnvironmentID returns one of the immutable alpha entries. The
// returned value does not contain an operator prepared-runtime pin.
func CatalogForEnvironmentID(environmentID string) (Catalog, bool) {
	for _, entry := range AlphaCatalogs() {
		if entry.EnvironmentID == environmentID {
			return entry, true
		}
	}
	return Catalog{}, false
}

func catalog(environmentID, gameVersion string, build uint32, paperSHA256 string, paperSize int64) Catalog {
	return Catalog{
		EnvironmentID: environmentID,
		Paper: PaperPin{
			GameVersion: gameVersion,
			Build:       build,
			Artifact: ArtifactPin{
				URI:       "https://fill-data.papermc.io/v1/objects/" + paperSHA256 + "/paper-" + gameVersion + "-" + strconv.FormatUint(uint64(build), 10) + ".jar",
				SHA256:    paperSHA256,
				Filename:  "paper-" + gameVersion + "-" + strconv.FormatUint(uint64(build), 10) + ".jar",
				SizeBytes: paperSize,
			},
		},
		Java: JavaPin{
			Distribution: "eclipse-temurin",
			Version:      "21.0.8+9",
			OS:           "linux",
			Architecture: "amd64",
			ArchiveRoot:  "jdk-21.0.8+9-jre",
			Artifact: ArtifactPin{
				URI:       "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.8%2B9/OpenJDK21U-jre_x64_linux_hotspot_21.0.8_9.tar.gz",
				SHA256:    "968c283e104059dae86ea1d670672a80170f27a39529d815843ec9c1f0fa2a03",
				Filename:  "OpenJDK21U-jre_x64_linux_hotspot_21.0.8_9.tar.gz",
				SizeBytes: 51_942_501,
			},
			MaximumExpandedBytes: 164_834_866,
		},
		ProbeVersion:      AlphaProbeVersion,
		ProbeSourceCommit: AlphaProbeSourceCommit,
		Probe: ArtifactPin{
			SHA256:    AlphaProbeSHA256,
			Filename:  "paper-probe.jar",
			SizeBytes: AlphaProbeSizeBytes,
		},
	}
}
