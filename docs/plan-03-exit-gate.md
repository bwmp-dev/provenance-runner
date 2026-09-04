# Plan 03 exit-gate evidence

Plan 03 acceptance is an exact-candidate, machine-verifiable CI run rather than
a prose-only report. The `Plan 03 acceptance` workflow builds the candidate
runner, rebuilds the trusted probe and all fixtures from their pinned source,
runs the real gVisor smoke and Paper/JVM matrix, and retains the resulting
`plan03-exit-gate-<candidate SHA>` artifact for 90 days.

The artifact is accepted only when its `manifest.sha256` verifies and every
fixture-specific assertion in `scripts/plan03-acceptance.sh` passes. The pull
request records the exact candidate SHA, workflow run URL, and artifact name.

## Trigger and accountability policy

Normal CI and the short real-gVisor smoke run on every pull request. The full
retained-evidence gate runs automatically when the workflow, harness, fixture
inventory, any command, or any module-internal package changes, except for the
four explicitly remote-only packages `internal/buildinfo`,
`internal/enrollment`, `internal/gatewayclient`, and
`internal/runneridentity`. The broad `cmd/**` and `internal/**` patterns make a
new command or internal package fail safe into the full gate unless it is
deliberately reviewed and excluded. An unfiltered Go test fixes that exclusion
set, rejects imports from covered internal packages into those packages, and
confines their command-level use to the enrollment and connection functions.

`go.mod` and `go.sum` changes do not run the full gate for every pull-request
revision. The integrator responsible for merging the pull request must classify
the frozen dependency diff. A Go toolchain change, or a direct or transitive
dependency change capable of altering artifact handling, evidence or complete
logs, local job decoding, Paper adaptation, process execution, workspace or
instance-lock behavior, gVisor OCI construction, structured event transport,
resource controls, cleanup, or reconciliation, requires a manual full-gate run
before merge. This includes relevant changes to `golang.org/x/sys`, the
Provenance toolkit protocol dependency, and Protobuf runtime dependencies.

Dispatch the workflow against the frozen pull-request head branch and verify
that the resulting run's `headSha` equals the intended head SHA. Record that
SHA, the run URL, and the `plan03-exit-gate-<SHA>` artifact name in the pull
request acceptance evidence. If the head moves, the run is stale and must be
repeated. Every merge that changes `go.mod` or `go.sum` also triggers one
post-main backstop run; that run must be green before the merged dependency
state is treated as integrated. The post-main backstop does not replace the
pre-merge manual run for a sandbox-relevant dependency change.

## Immutable inputs

- gVisor nightly `2026-08-30`, runsc
  `release-20260824.0-86-geeff98ba9777`; archive SHA-512
  `e8eb6473e5a27316df551cbb40e5626e51df1b602bde2621f77d851c2c53b0387e282c7ebc0ee80ceb07a26e152e67b4af3e17550009e2c486e2f19666570449`;
  extracted runsc SHA-256
  `456ea862b62b48bb7ff27ae38c262b52315bf3d68ea0733164e4817cadc518a1`.
- Alpine 3.24.1 smoke root filesystem archive SHA-512
  `de367c4fd4b5a2ab17f30fe62b135b98acd76c22014abdf51285588bde0edb7275265a84400418a5dab8cbdec36b3a41ca1312ca3af8e54438036455f26d72c1`.
- Ubuntu 24.04 Paper root filesystem image
  `sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517`.
- Paper 1.21.8 build 60: 52,811,717 bytes, SHA-256
  `8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e`.
- Temurin JRE 21.0.8+9: 51,942,501 bytes, SHA-256
  `968c283e104059dae86ea1d670672a80170f27a39529d815843ec9c1f0fa2a03`.
- Probe and all fixtures: source commit
  `c4bf6bc9ddd0be3221e897e0ee9e2d409d206dec`. The probe is 478,837 bytes
  with SHA-256
  `abbccf45831ef998466542b19169731b9ec4f8a6c3525fce4d7a2c0b5f4b4b43`.
- Prepared Paper runtime: 153,958,528 compressed bytes and 163,396,442
  expanded bytes, SHA-256
  `ba1434cfc3af6fe145660e82f5b07ce9cb46cbc76d23c68a767a3717e7e5ca57`.

Every artifact is verified before cache seeding and is verified again by
`artifact.Cache.AcquireExact` before materialization. Paper is downloaded with
the required Provenance user agent.

## Retained bundle

The artifact contains:

- `runner-head.txt`: the exact checked-out candidate used to build the runner;
- `identities.txt` and `assets.tsv`: host, cgroup, runsc version, runner/runsc
  hashes, and every verified asset identity;
- `fixtures.tsv` and `jobs/*.json`: the reviewed expected outcomes and exact
  standalone CLI inputs;
- `results/*.json`, `results/*.stderr`, and `results/*.log.gz`: structured
  results and complete sanitized gzip logs for all 14 fixtures;
- `resources/*.ndjson`: repeated real cgroup and `runsc events --stats`
  samples, including configured CPU/memory/PID controls, CPU throttling,
  memory events, sandbox task count, memory/CPU usage, and network interfaces;
- `summary.ndjson`: one compact accepted result per fixture; and
- `manifest.sha256`: hashes for every other retained file.

After downloading and entering the artifact directory, verification is:

```sh
sha256sum --check --strict manifest.sha256
for log in results/*.log.gz; do gzip --test "$log"; done
test "$(wc -l < summary.ndjson)" -eq 16
```

## Observable acceptance paths

The real-runsc smoke covers normal execution, deadline cancellation, and
startup reconciliation of an intentionally abandoned live container. It
asserts UID/GID 65532, read-only root, writable bounded tmpfs mounts, absent
Docker socket, failed private-address and metadata-address connections, and no
exact-ID process, mount, network-namespace holder, bundle, state, or job-cgroup
residue.

The Paper matrix covers success, command success, both lifecycle failures,
missing dependency, command assertion failure, enable hang, explicit process
exit, memory exhaustion, PID exhaustion, disk exhaustion, network scan,
metadata endpoint access, and log flood. Resource attacks use isolated classes
chosen to make the intended boundary observable:

- ordinary fixtures: 1,000 CPU millis, 2 GiB memory, 128 tasks, 1 GiB disk;
- memory bomb: 1.5 GiB, with nonzero `oom_kill`, target enable, and exit 137
  required; and
- PID bomb: 4 GiB and 48 tasks, with nonzero sandbox task telemetry remaining
  at or below the configured bound, and either a nonzero host-cgroup
  `pids.events:max` denial count or at least 10 continuous seconds at
  `pids.max` required. The fixture handles bounded fork pressure and the server
  must still shut down cleanly.

All classes use network `none`, zero connections, and zero bandwidth. Network
fixtures must reach target enable while runtime samples expose no interface
other than loopback. Disk exhaustion must retain `No space left on device`.
Timeout cases must reach their configured wall bound.

The log-flood assertion proves bounded live output and a separate complete
archive: the live projection must be exactly 65,536 bytes and marked
truncated, the archive must exceed the live projection by more than 10x and
remain within 100 KiB of raw observed bytes after structured-event
separation, and at least 10,000 flood lines must be present in the gzip. Every
result's gzip size and SHA-256 must match the exported file, and the configured
secret must be absent from JSON, stderr, and the decompressed archive.

After every fixture, the harness audits the actual OCI cgroup path
`<delegated parent>/provenance/provenance-<container ID>` recursively, then
checks exact container IDs across `/proc/*/cmdline`, mount information, and
network namespace holders. Bundle, state, and writable workspace roots must be
empty before the next fixture starts.

## Acceptance mapping

- WP-03A: the generic provider lifecycle and local JSON path are exercised by
  focused executor tests and every retained CLI job. Paper remains selected
  through the generic registry.
- WP-03B: exact Paper, Java, probe, prepared-runtime, target, and dependency
  identities are retained. Cache concurrency, redirect/SSRF rules, archive
  bounds, empty workspace construction, minimal configuration, and test-plan
  construction remain covered by focused race tests.
- WP-03C: OCI unit tests assert the static boundary, while the real smoke,
  runtime stats, hostile fixtures, cancellation, reconciliation, and residue
  scans exercise it. Only network `none` is claimed.
- WP-03D: probe events remain separate from raw logs; UTF-8 normalization,
  ANSI removal, redaction, line caps, bounded live output, independent complete
  gzip retention, secure export, hashes, usage, resource class, wall time, and
  environment identity have focused and live coverage.

Repository verification remains:

```sh
test -z "$(gofmt -l .)"
go vet ./...
go build ./cmd/provenance-runner
go test -race -count=1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

No Protobuf, OpenAPI, or operator configuration contract changes are part of
this exit gate. The known trust limitation is unchanged: the target plugin
shares the sandbox JVM and UID with the trusted probe, so bounded probe events
are validated but not cryptographically attributable.
