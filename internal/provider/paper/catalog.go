package paper

const (
	AlphaEnvironmentID     = "paper-1.21.8-60-linux-amd64-temurin-21.0.8+9"
	AlphaProbeVersion      = "0.1.0"
	AlphaProbeSourceCommit = "0741914e16dee1476d8bbd8d7d370eaf8a0eb0c2"
	AlphaProbeSHA256       = "cc981edc49a1fc27a920c3e39415428d3897eb878e748a6ad2b708972ef6e082"
	AlphaProbeSizeBytes    = int64(462_392)
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
	return Catalog{
		EnvironmentID: AlphaEnvironmentID,
		Paper: PaperPin{
			GameVersion: "1.21.8",
			Build:       60,
			Artifact: ArtifactPin{
				URI:       "https://fill-data.papermc.io/v1/objects/8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e/paper-1.21.8-60.jar",
				SHA256:    "8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e",
				Filename:  "paper-1.21.8-60.jar",
				SizeBytes: 52_811_717,
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
