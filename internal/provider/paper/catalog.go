package paper

import "strconv"

const (
	Paper1206EnvironmentID = "paper-1.20.6-151-linux-amd64-temurin-21.0.8+9"
	Paper1214EnvironmentID = "paper-1.21.4-232-linux-amd64-temurin-21.0.8+9"
	AlphaEnvironmentID     = "paper-1.21.8-60-linux-amd64-temurin-21.0.8+9"
	AlphaProbeVersion      = "0.1.0"
	AlphaProbeSourceCommit = "98d5f07f173a9e3f1b365add24b81c934d7e3c61"
	AlphaProbeSHA256       = "abbccf45831ef998466542b19169731b9ec4f8a6c3525fce4d7a2c0b5f4b4b43"
	AlphaProbeSizeBytes    = int64(478_837)
	DownloadUserAgent      = "Provenance-Runner/0.1.0 (https://github.com/bwmp-dev/provenance-runner)"
)

type ArtifactPin struct {
	URI       string
	SHA256    string
	Filename  string
	SizeBytes int64
}

type PaperPin struct {
	GameVersion string
	Build       uint32
	Artifact    ArtifactPin
}

type JavaPin struct {
	Distribution         string
	Version              string
	OS                   string
	Architecture         string
	ArchiveRoot          string
	Artifact             ArtifactPin
	MaximumExpandedBytes int64
}

type ArchivePin struct {
	Artifact             ArtifactPin
	MaximumExpandedBytes int64
}

type Catalog struct {
	EnvironmentID     string
	Paper             PaperPin
	Java              JavaPin
	ProbeVersion      string
	ProbeSourceCommit string
	Probe             ArtifactPin
	PreparedRuntime   ArchivePin
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
