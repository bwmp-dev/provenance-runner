# Provenance runner + platform threat model

**Status: Draft — requires security-lead sign-off.**

Focused review of the highest-consequence paths across the hosted runner
(`bwmp-dev/provenance-runner`) and the platform (`bwmp-dev/provenance-platform`,
read read-only for context): plugin upload, sandbox escape, SSRF, credential
exposure, cross-tenant access, and publication. File references without a repo
prefix are in `provenance-runner`; platform references are prefixed
`platform:`. Each section lists assets, entry points, controls with references,
residual risks, and linked tests/evidence. Residual risk IDs (R-*) are
referenced from the tests that pin them.

Trust model: every customer JAR and its output is hostile
(`AGENTS.md`). Hosted execution must use gVisor, non-root processes, isolated
namespaces, dropped capabilities, quotas, timeouts, bounded output and
guaranteed cleanup. The runner must never accept database, Temporal,
marketplace or platform-management credentials.

## 1. Plugin upload

**Assets:** customer plugin JARs and dependencies; object storage integrity;
runner host and sandbox.

**Entry points:** platform upload API
(`platform:internal/api/artifacts.go` — `POST /v1/projects/{projectId}/artifacts/uploads`,
`POST /v1/artifacts/{artifactId}/complete`) issuing presigned S3 PUTs; the
runner's lease offer artifact/dependency descriptors and the subsequent HTTPS
download; sandbox input staging.

**Controls:**
- Upload requires a bearer token or session cookie plus an idempotency key;
  size cap 512 MiB (`platform:internal/api/artifacts.go:17`, `config.go:108`);
  filename ≤255 chars, no separators or control characters
  (`platform:internal/artifacts/service.go:768`). On complete the platform
  recomputes SHA-256 and size from the staged object and rejects mismatches
  (`platform:internal/artifacts/stored.go`, `service.go:376-407`).
- The runner never trusts upload metadata: it re-verifies size and digest
  before materialization (`internal/artifact/cache.go` `AcquireExact`;
  `internal/provider/paper/provider.go:562-590`) and binds bytes by digest.
  Offer admission rejects path-like/oversized/SSRF/duplicate/digest-substituted
  descriptors (`internal/gatewayclient/offer_validation.go` —
  `validateOfferDownloads`, `validateObjectDownload`, `validPluginFilename`).
- The runner **never parses JAR contents on the host.** Archives are staged as
  opaque, read-only bytes under fixed aliases (`target.jar`,
  `dependency-NNN.jar`) and exposed to the guest only via a read-only,
  `noexec,nosuid,nodev` `/inputs` bind mount
  (`internal/provider/gvisor/oci.go`,
  `internal/provider/gvisor/measured_inputs_linux.go`). Any archive parsing
  (zip bomb, traversal, manifest) happens inside the sandbox as Paper's problem.

**Residual risks:**
- **R-UP-1** The platform performs no JAR/zip/`plugin.yml` inspection and no
  malware/zip-bomb scan on upload (`platform` has no `archive/zip` use on the
  customer path). Zip bombs and hostile archives are contained only at
  execution time by sandbox disk/CPU/memory quotas, not rejected at rest.
- **R-OFFER-1** Offer admission accepts non-separator control characters inside
  a plugin filename (`validPluginFilename` blocks only `/`, `\`, NUL and
  trims). The filename is descriptor metadata; inputs are materialized under
  fixed aliases, so this does not reach the filesystem. Pinned by
  `TestOfferFilenameControlCharactersAreDescriptorsOnly`.

**Tests/evidence:** `internal/provider/gvisor/hostile_input_test.go`
(`TestHostileJarsAreOpaqueReadOnlyInputs`, `TestHostileJarCorpusIsGenuinelyHostile`,
`FuzzGVisorJobConfiguration`); `internal/provider/gvisor/hostile_measured_input_linux_test.go`;
`internal/gatewayclient/hostile_input_test.go`
(`TestValidateOfferRejectsHostileArtifactDescriptors`, `FuzzValidateOffer`);
`internal/workspace/archive_link_boundary_test.go`; `internal/artifact/cache_test.go`.

## 2. Sandbox escape

**Assets:** runner host kernel, other jobs, host network and credentials.

**Entry points:** the guest process (customer JAR under Paper/JVM); guest
stdout/stderr and the structured-event channel; job configuration.

**Controls:** gVisor (`runsc`) with hardened flags — `--network=none`,
`--net-raw=false`, `--host-uds=none`, `--allow-suid=false`,
`--overlay2=none`, `--directfs=false`, `--file-access=exclusive`
(`internal/provider/gvisor/provider.go`, `oci.go`). Guest runs as UID/GID 65532,
read-only root, `NoNewPrivileges`, all capability sets empty, fresh
pid/network/mount/ipc/uts/cgroup namespaces (never host namespace paths),
CPU/memory/PID/disk cgroup limits and `RLIMIT_NPROC`/`RLIMIT_FSIZE`, no Docker
socket or host device bind mounts (`TestPrepareWritesContainedOCIConfiguration`).
Wall/preparation/graceful timeouts and guaranteed cleanup with residue checks
(`internal/provider/gvisor/teardown.go`, `smoke_linux_test.go`). Bounded,
sanitized output (§4).

**Residual risks:**
- **R-ESC-1** Isolation ultimately depends on gVisor kernel correctness; a
  `runsc` sandbox-escape vulnerability would bypass these controls. Mitigated by
  the pinned gVisor version/SHA and the exact-head Plan 03 gate
  (`docs/plan-03-exit-gate.md`), not eliminated.
- **R-ESC-2** The measured-runtime path additionally trusts the operator-built
  rootfs image identity; drift is detected (`gvisor_runtime_measurement_drift`)
  but a compromised builder is out of scope for the runner.

**Tests/evidence:** `internal/provider/gvisor/isolation_probe_linux_test.go`
(`TestIsolationProbeSandboxDeniesEscapes`) and
`testdata/hostile/isolation-probe` (PostgreSQL 5432, Temporal 7233, Coolify
host, metadata, Docker/containerd sockets, `/proc/1/ns`, cross-job reads, env
scraping — all denied); `smoke_linux_test.go` `TestRunscSmoke`;
`provider_test.go` (`TestPrepareWritesContainedOCIConfiguration`,
`TestResolveRejectsUnsafeOrUnboundedConfiguration`); the Plan 03 hostile matrix;
`.github/workflows/network-policy.yml`.

## 3. SSRF

**Assets:** cloud metadata credentials, private/management services
(PostgreSQL 5432, Temporal 7233, Coolify host), other tenants.

**Entry points:** runner artifact/dependency download URLs and redirects; guest
network attempts; platform dependency resolution and webhooks.

**Controls:**
- Download URLs must be HTTPS, no userinfo, no fragment, host is not a literal
  IP or `localhost`, port empty or 443 (`offer_validation.go:314`;
  `internal/provider/paper/provider.go:403`). The download client re-resolves
  every host and refuses any non-public resolved address, disables proxies and
  custom dialers, and re-validates redirects
  (`internal/provider/paper/source.go` — `clientWithSourcePolicy`,
  `secureDialContext`, `validateResolvedAddress`).
- The public/grantable-address classifier rejects metadata, loopback, private,
  link-local, multicast, IPv4-mapped and non-global-unicast IPv6
  (`internal/networkpolicy/addresses.go` `Binder.public`, `special`).
- The guest sandbox is `network=none`; effective network permission is the
  intersection of all policy layers (`AGENTS.md`, `offer_validation.go`
  `validateOfferPolicyVersion`).
- Platform: no customer-supplied fetch URLs; Modrinth host allowlisted, webhook
  restricted to discord.com (`platform:internal/dependencies/modrinth.go`,
  `internal/alerts/discord.go`).

**Residual risks:**
- **R-SSRF-1** Runner SSRF defense depends on DNS re-resolution at dial time;
  the `secureDialContext` TOCTOU window is closed by validating every resolved
  address and dialing the resolved IP, but a resolver that returns a public
  address then a private one on re-lookup is only defeated because the dialed
  address is the validated one — reviewers should confirm no code path dials by
  hostname after validation.
- **R-SSRF-2** Platform Paper catalog accepts any HTTPS host for the server
  download (`platform:internal/catalog/client.go:315`); operator-driven and
  SHA-256-pinned, but not private-IP-blocked.

**Tests/evidence:** `internal/networkpolicy/hostile_address_test.go`
(`TestBinderNeverTreatsManagementOrMetadataAddressesAsPublic`,
`FuzzBinderPublicAddress`); `internal/gatewayclient/hostile_input_test.go`
(SSRF URI cases in `TestValidateOfferRejectsHostileArtifactDescriptors`);
`internal/provider/paper/source_test.go`; the isolation probe (§2).

## 4. Credential exposure

**Assets:** DB/Temporal/object-storage/management credentials; test secrets;
signed download/upload URLs; runner enrollment credentials.

**Entry points:** guest log output; structured results; complete-log upload;
runner-side credential storage; test-secret delivery.

**Controls:**
- The runner accepts **no** database/Temporal/marketplace/management
  credentials (`AGENTS.md`); it receives only short-lived presigned URLs and,
  when enabled, scoped test secrets.
- All guest output is normalized (ANSI/OSC stripped, UTF-8 repaired),
  redacted against the configured secret set at every chunk boundary, and
  bounded per line and in total before it leaves the host
  (`internal/evidence/collector.go`, `processor.go`, `redaction.go`;
  `FuzzRedactionChunkIndependent`). Only bounded live batches and structured
  results traverse the gateway; complete logs go to object storage
  (`internal/gatewayclient/live_evidence.go`, `complete_log_upload.go`).
- Test-secret delivery is refused unless explicitly negotiated and is validated
  on the wire before decoding (`internal/gatewayclient/strict_protocol_codec.go`,
  `secret_exchange.go`, `internal/testsecrets`). Credential storage rejects
  symlink/hardlink/mode substitution
  (`internal/gatewayclient/credential_store_linux.go`).

**Residual risks:**
- **R-LOG-1** Sanitization strips ESC-initiated sequences and repairs UTF-8 but
  intentionally preserves other C0 controls (NUL, BEL, BS) and the UTF-8-encoded
  C1 CSI verbatim in logs. Downstream consumers that render logs in a terminal
  or HTML must escape them. Pinned by
  `TestHostileGuestOutputIsBoundedSanitizedAndClassified`.
- **R-CRED-1** Redaction only removes secrets the runner was told about
  (`RedactSecrets` / test-secret values). A credential a plugin fabricates or
  derives is not redacted; the control is "runner holds no standing
  credentials," not "logs are secret-free."
- **R-CRED-2** Platform has no central log-redaction layer; it relies on
  per-type `String()` redaction and conventions
  (`platform:internal/testsecrets/cipher.go:80`).

**Tests/evidence:** `internal/provider/gvisor/hostile_input_test.go`
(`TestHostileGuestOutputIsBoundedSanitizedAndClassified`);
`internal/evidence/*redaction*_test.go`, `structured_boundary_test.go`;
`internal/gatewayclient/credential_store_linux_test.go`,
`secret_stream_linux_test.go`, `test_secret_delivery_test.go`.

## 5. Cross-tenant access

**Assets:** one organization's jobs, inputs, logs, results, artifacts.

**Entry points:** runner job identifiers and inputs directories; gateway lease
scope; platform API authorization.

**Controls:**
- The runner runs one job at a time; job IDs are strictly validated
  (`internal/provider/gvisor/provider.go:306`), inputs are confined to a
  per-job directory that cannot be a symlink or escape the inputs root
  (`validateInputPath`), and one job's mounts never reference another. Offers
  are admitted only for the runner's expected organization/platform scope
  (`offer_validation.go` `validateOfferScope`, `validateOfferJobCorrelation`).
- Platform: app-level tenant scoping on every query
  (`platform:db/queries/*`, `internal/identity/session.go`,
  `internal/authz/authz.go`); cross-org reads return 404, cross-project 403.

**Residual risks:**
- **R-TEN-1** Platform has no PostgreSQL row-level security; isolation depends
  entirely on every query filtering `organization_id`. A missing filter in a
  new query would silently leak across tenants; RLS as defense in depth is not
  present.

**Tests/evidence:** `internal/provider/gvisor/hostile_input_test.go`
(`TestJobInputsNeverExposeAnotherJob`); the isolation probe cross-job read;
`internal/gatewayclient/offer_validation_test.go` scope cases;
`platform:internal/api/artifacts_integration_test.go` and
`release_candidates_integration_test.go`.

## 6. Publication

**Assets:** signed attestations, public verification badges, marketplace
publications, signing keys.

**Entry points:** platform publication workers and public verification API
(runner produces only signed results consumed downstream).

**Controls:** Ed25519 attestation signing with mode-0400 PKCS8 keys bound to a
single domain (`platform:internal/attestations/*`,
`internal/attestationcustody`); public disclosure only through explicit
`public_verification_releases` rows, re-verified on every read; badge only for
hosted records with all required environments passed
(`platform:internal/attestations/PUBLIC.md`, `internal/api/public_verification.go`);
marketplace adapters require a transaction-scoped `PublicationAuthorizer` and
fail closed (`platform:internal/publishing/*`). Only publishing workers may
decrypt publishing credentials.

**Residual risks:**
- **R-PUB-1** Publication exposes the entire signed statement publicly (source
  repo/commit, dependencies, runner identities). Confidential metadata must not
  enter attested fields; this is a data-classification control, not enforced by
  the signing path.
- **R-PUB-2** Badge/publication integrity depends on the runner's classification
  being trustworthy; a runner that mis-classified a hostile job as passed would
  taint the badge. Mitigated by the exact-head Plan 03 gate and the
  product-vs-infrastructure classification tests, not independently verified
  post-hoc.

**Tests/evidence:** `platform:internal/attestations/*_test.go`,
`internal/publishing/*integration_test.go`,
`internal/publicationcomposition/transactions_integration_test.go`; runner
classification: `internal/provider/gvisor/hostile_input_test.go`,
`internal/execution/failure_stage_test.go`.

## Image scanning

`.github/workflows/ci.yml` runs `govulncheck` (reachability-aware Go vuln scan)
and a pinned Trivy `filesystem` scan (`--scanners vuln,misconfig,secret`,
HIGH/CRITICAL, pinned version + tarball SHA-256) over the repository — the
supply-chain, Dockerfile/config and committed-secret surface a runner
container image or VPS bundle is built from. The runner ships as a Go binary
plus systemd units; no runner container image is published from this repo, and
the CI-built images (network-policy fixtures, measured rootfs) are ephemeral
test scaffolding, so the honest target is the repository filesystem rather than
a published image.
