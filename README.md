# Provenance Runner

Public Go runner for hosted and self-hosted Provenance execution.

The current alpha accepts one bounded local job document and emits one structured result:

```sh
go run ./cmd/provenance-runner execute job.json
```

The gateway client is not wired yet. The local job's `provider` selects one of two implementations:

- `development-process` executes directly on the host after the job explicitly sets `"acknowledgeUnsandboxed": true`. It exists only for runner-core development and is not a security boundary.
- `paper` prepares a pinned Paper environment and delegates execution to gVisor. It is Linux-only and fails initialization unless the trusted host supplies all required operator configuration.

## Paper operator configuration

The trusted host must set these variables before executing a `paper` job:

```text
PROVENANCE_PAPER_PROBE_URI
PROVENANCE_PAPER_PROBE_SHA256
PROVENANCE_PAPER_PROBE_SIZE_BYTES
PROVENANCE_PAPER_PREPARED_RUNTIME_URI
PROVENANCE_PAPER_PREPARED_RUNTIME_SHA256
PROVENANCE_PAPER_PREPARED_RUNTIME_SIZE_BYTES
PROVENANCE_PAPER_PREPARED_RUNTIME_MAX_EXPANDED_BYTES
PROVENANCE_ARTIFACT_HOSTS
PROVENANCE_WORKSPACE_ROOT
PROVENANCE_CACHE_ROOT
PROVENANCE_RUNSC_PATH
PROVENANCE_ROOTFS
PROVENANCE_ROOTFS_IDENTITY
PROVENANCE_GVISOR_STATE_ROOT
PROVENANCE_GVISOR_BUNDLE_ROOT
```

`PROVENANCE_ARTIFACT_HOSTS` is a comma-separated exact DNS-host allowlist for job-provided target and dependency downloads. The probe and prepared runtime use their exact operator URI, SHA-256, and byte-size pins. The prepared-runtime archive contains offline Paperclip cache, library, and patched-runtime output; it must omit the paths where the runner overlays `paper.jar`, plugins, the EULA, minimal server properties, and the test plan.

The alpha Paper provider accepts only probe `0.1.0` built from Provenance commit `0741914e16dee1476d8bbd8d7d370eaf8a0eb0c2`: SHA-256 `cc981edc49a1fc27a920c3e39415428d3897eb878e748a6ad2b708972ef6e082`, 462392 bytes. The JAR is reproducible from that commit, but the current public Provenance release does not publish probe bytes, so the operator must host those exact bytes and supply their HTTPS URI.

Optional limits are `PROVENANCE_MAX_ARTIFACT_BYTES`, `PROVENANCE_MAX_DEPENDENCY_BYTES`, `PROVENANCE_MAX_PREPARATION_BYTES`, and `PROVENANCE_MAX_CACHE_BYTES`. `PROVENANCE_GVISOR_PLATFORM` may be `systrap` (the default) or `kvm`. Implementation hard limits still apply.

Only one Paper CLI process may use a gVisor bundle root at a time. The runner holds an operating-system-backed exclusive lock for the full invocation so startup reconciliation cannot remove another invocation's prepared or running bundle. Lock contention fails runner initialization rather than waiting indefinitely.

## Paper local-job input

The `paper` environment uses the pinned environment ID `paper-1.21.8-60-linux-amd64-temurin-21.0.8+9`. It requires:

- `artifactKind: "minecraft-plugin"`;
- `target` with an HTTPS `uri`, lowercase hexadecimal `sha256`, plain JAR `filename`, and authoritative positive `sizeBytes`;
- optional dependencies with an `id`, expected Paper plugin name, and the same artifact fields;
- a test plan containing the target Paper plugin name and any required dependency plugin names;
- explicit memory, CPU-millis, PID, and disk limits.

The job cannot provide or replace the trusted probe, Paper, Java, prepared runtime, host paths, gVisor configuration, or download allowlist. Runtime network access is `none`.

The Paper provider's `AdaptJob` boundary consumes the released runner `JobSpecification`. Every target and dependency `ObjectDownload` must declare a positive `size_bytes`, match its job hash, and fit the provider's configured per-artifact, dependency, and preparation quotas. Those exact sizes flow into the content-addressed cache, which rejects short and oversized responses before workspace creation. The adapter materializes `tests.console` into the trusted probe plan and accepts only the reviewed lifecycle and command event/classification inventory. The gateway transport is not wired yet.

## Current evidence limits

Unit and hosted CI exercise preparation, bounded evidence, quotas, download policy, cleanup, and gVisor bundle construction. The hosted gVisor smoke test skips when `runsc` is absent. There is not yet live Paper/JVM, hostile-fixture, or real runsc execution evidence for this slice.

Probe lifecycle output is bounded and fails closed on missing, malformed, duplicate, out-of-order, or failed assertions. It is not cryptographically attributable: the tested plugin shares the JVM and sandbox UID and could attempt to forge or modify the reserved event channel.
