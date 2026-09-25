# Hostile fixture inventory

Every hostile / malformed-input fixture in the runner repository, what it
proves, and how to run it. The single entry point is
`scripts/hostile-fixtures.sh` (see the header of that script for flags).

- **Host-safe** fixtures run in ordinary `go test -race ./...` and in the
  default `scripts/hostile-fixtures.sh` invocation. They use fake runsc command
  runners and in-memory data; no sandbox is launched and no hostile payload is
  executed.
- **gVisor** fixtures need a prepared read-only root filesystem mount plus
  gVisor. They run on the self-hosted CI runner (`gvisor-smoke` job and the
  `Plan 03 acceptance` workflow) and on a disposable local root+gVisor host, via
  `scripts/hostile-fixtures.sh --gvisor` with `PROVENANCE_RUNSC_SMOKE=1`,
  `PROVENANCE_RUNSC_PATH`, `PROVENANCE_RUNSC_ROOTFS` exported.

Never run the gVisor or Plan 03 tiers against production. In-sandbox probes
target only well-known private/management and metadata addresses, and only from
inside a `network=none` sandbox where no packet can leave the guest
(runner `AGENTS.md`: hostile fixtures run only in a disposable Linux
environment).

## Malformed / hostile input (host-safe, added in WP-11C)

| Fixture | Boundary | Proves | Run |
| --- | --- | --- | --- |
| `TestHostileJarCorpusIsGenuinelyHostile` | plugin JAR corpus | The zip-bomb, path-traversal, duplicate-entry, huge-manifest, non-zip, truncated and empty JAR fixtures are genuinely malformed (guards the corpus) | `go test ./internal/provider/gvisor -run TestHostileJarCorpusIsGenuinelyHostile` |
| `TestHostileJarsAreOpaqueReadOnlyInputs` | job inputs → /inputs mount | Hostile JARs are never inflated, rewritten or path-resolved; exposed only via a read-only noexec/nosuid/nodev mount; bytes unchanged; no traversal entry materializes; host footprint bounded by compressed size | `go test ./internal/provider/gvisor -run TestHostileJarsAreOpaqueReadOnlyInputs` |
| `TestJobInputsNeverExposeAnotherJob` | job inputs isolation | Job identifiers cannot traverse to another job; a symlinked job input directory fails closed as infrastructure; one job's mounts never reference another | `go test ./internal/provider/gvisor -run TestJobInputsNeverExposeAnotherJob` |
| `TestMeasuredStagingTreatsHostileJarsAsOpaqueBytes` | measured (hosted) input staging | Hosted staging copies exact bytes under a fixed alias, never interprets archive entries, refuses digest/size/alias mismatch without residue (requires real root; runs in the privileged gVisor job) | privileged CI job, or local root |
| `TestHostileGuestOutputIsBoundedSanitizedAndClassified` | guest stdout/stderr → evidence + live observer | Oversized / control-char / invalid-UTF-8 / ANSI-OSC / secret / forged-structured-event output stays bounded, sanitized (ESC-free, valid UTF-8, redacted), classified product-not-infrastructure; complete log gzip is bounded and sanitized | `go test ./internal/provider/gvisor -run TestHostileGuestOutputIsBoundedSanitizedAndClassified` |
| `FuzzGVisorJobConfiguration` | local job + gVisor environment decoder | Any accepted job still yields the hardened sandbox invariants; everything else fails closed as `invalid_job` before runsc | `go test ./internal/provider/gvisor -run '^$' -fuzz=FuzzGVisorJobConfiguration` |
| `TestValidateOfferRejectsHostileArtifactDescriptors` | gateway lease offer admission | Path-like / control / oversized / SSRF / digest-substituted / disk-overflow / duplicate artifact and dependency descriptors are refused as stable product rejections without mutating the offer | `go test ./internal/gatewayclient -run TestValidateOfferRejectsHostileArtifactDescriptors` |
| `FuzzValidateOffer` | gateway lease offer admission | Arbitrary offer protobufs never panic or mutate input; rejections are bounded/stable; admitted offers satisfy isolation, capacity, disk and digest-binding invariants | `go test ./internal/gatewayclient -run '^$' -fuzz=FuzzValidateOffer` |
| `TestStrictCodecRefusesMalformedGatewayFrames` | gateway wire codec | Truncated / oversized / wrong-wire-type / duplicate-correlation / hidden-secret protobuf frames fail closed before generated decoding | `go test ./internal/gatewayclient -run TestStrictCodecRefusesMalformedGatewayFrames` |
| `FuzzStrictGatewayCodecAndHandlers` | gateway wire codec + session handlers | Arbitrary frames never panic, exceed the frame bound, deliver an unsolicited secret, or create an active job without a worker | `go test ./internal/gatewayclient -run '^$' -fuzz=FuzzStrictGatewayCodecAndHandlers` |
| `TestLiveLogChunkingBoundsHostileOutput` / `FuzzLiveLogChunkSize` | live log projection | Oversized / invalid-UTF-8 / control-char output is chunked bounded, ordered, lossless; unknown streams dropped; no super-linear blowup | `go test ./internal/gatewayclient -run 'LiveLogChunk'` |
| `TestBinderNeverTreatsManagementOrMetadataAddressesAsPublic` / `FuzzBinderPublicAddress` | network policy address classifier | Metadata, loopback, private, link-local, multicast and IPv4-mapped encodings are never classified as public/grantable | `go test ./internal/networkpolicy -run 'ManagementOrMetadata|FuzzBinderPublic'` |

## Isolation probe (gVisor)

| Fixture | Form | Proves | Run |
| --- | --- | --- | --- |
| `TestIsolationProbeSandboxDeniesEscapes` | shell, in real runsc | PostgreSQL 5432, Temporal 7233, Coolify management host, cloud metadata, Docker/containerd sockets, host PID/net namespaces, cross-job reads and env credential scraping are all denied inside a `network=none` sandbox; guest runs as UID 65532 | `scripts/hostile-fixtures.sh --gvisor` |
| `testdata/hostile/isolation-probe` | Paper plugin JAR (source + build) | Same attack surface through a real customer JAR in the Plan 03 matrix (`-Dprovenance.fixture.hostile.enabled=true`) | build per its README, run via `scripts/plan03-acceptance.sh` on a gVisor host |

## Pre-existing hostile fixtures (retained)

| Fixture | Tier | Proves |
| --- | --- | --- |
| `internal/provider/gvisor` `TestRunscSmoke` "contained execution" | gVisor | UID 65532, read-only root, no Docker socket, no route, failed private + metadata connections, no sandbox residue |
| `internal/provider/gvisor` `TestExecuteUsesHardenedRunscFlagsAndCollectsBoundedOutput`, `TestResolveRejectsUnsafeOrUnboundedConfiguration`, `TestResolveRejectsUnsafeStructuredEventFile` | host-safe | hardened runsc flags; unsafe/unbounded configuration rejected; unsafe structured-event FIFO rejected |
| `internal/workspace` `TestArchiveRefusedLinkTreeIsNeverPublished`, `TestArchiveLinkRefusesEarlierSymlinkParent`, `archive_link_boundary_test.go` | host-safe | tar/gzip extraction bounds entries and expanded bytes and refuses traversal / symlink-parent escapes |
| `internal/evidence` `TestCollectorCapsOutputFloodWithMarker`, `TestCollectorDoesNotLetMalformedANSIEscapesHideLineBoundaries`, `TestCollectorRedactsSecret*`, `FuzzRedactionChunkIndependent` | host-safe | output flood cap, ANSI-hiding defeated, chunk-boundary secret redaction |
| `internal/gatewayclient` `TestMeasuredLauncherRejectsHostileInputsWithoutEcho`, `TestCredentialStoreRejectsSymlinkHardlinkModes...`, `TestRestartEvidenceAppendRejectsHardLinkedSource` | host-safe | launcher/credential/restart-evidence paths reject hostile inputs and unsafe file modes |
| `internal/testsecrets` `FuzzSecretSelectionBoundedJSON`; `internal/networkpolicy` `FuzzWorkloadDNSBoundedWire`, `FuzzDNSResponse` | host-safe | bounded JSON secret selection; bounded DNS wire parsing |
| `scripts/plan03-acceptance.sh` Paper/gVisor matrix (`testdata/plan03/fixtures.tsv`) | gVisor, `workflow_dispatch` | success, both lifecycle failures, missing dependency, command assertion, enable hang, process exit, memory bomb, fork/PID bomb, disk fill, network scan, metadata endpoint, log flood — see `docs/plan-03-exit-gate.md` |
| `.github/workflows/network-policy.yml` (`scripts/network-policy/*`) | gVisor/namespaces, push | routed packet policy, DNS, namespace and job-cgroup containment |

## What ran where

- **Locally (this change):** all host-safe Go hostile tests under `-race`; all
  fuzz seed corpora; bounded native fuzzing of every new target; the Plan 03
  contract checks; `scripts/hostile-fixtures.sh` end to end.
- **CI-only here:** the real-runsc smoke, the isolation probe, the measured
  staging test and the full Plan 03 Paper/gVisor matrix. They require a
  read-only rootfs mount and gVisor; the local dev environment for this change
  had no passwordless `sudo` to prepare that mount, so those tiers run on the
  self-hosted CI runner.
