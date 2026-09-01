# Plan 03 exit-gate evidence

This document retains the standalone-runner acceptance run performed on
2026-09-01. The candidate was based on
`ee0b747fb2af97823c17f498d93abec85e798af5`; the pull-request head containing
this document is the reviewed implementation candidate. This is the sanitized
reviewed projection; raw Paper logs were not committed because they contain
machine-local preparation paths.

## Immutable inputs

- Host: Linux amd64, kernel `6.8.0-138-generic`, cgroup v2.
- Disposable outer environment: Ubuntu 24.04 image
  `sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517`.
- gVisor nightly `2026-08-30`, runsc
  `release-20260824.0-86-geeff98ba9777`; archive SHA-512
  `e8eb6473e5a27316df551cbb40e5626e51df1b602bde2621f77d851c2c53b0387e282c7ebc0ee80ceb07a26e152e67b4af3e17550009e2c486e2f19666570449`;
  runsc SHA-256
  `42c71fabba1820c53ae11b8870956b7a066ba892d2e3be7b69433583fb6a5b0a`.
- Real-smoke root filesystem: Alpine 3.24.1 archive SHA-512
  `de367c4fd4b5a2ab17f30fe62b135b98acd76c22014abdf51285588bde0edb7275265a84400418a5dab8cbdec36b3a41ca1312ca3af8e54438036455f26d72c1`.
- Paper 1.21.8 build 60: 52,811,717 bytes, SHA-256
  `8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e`.
- Temurin JRE 21.0.8+9: 51,942,501 bytes, SHA-256
  `968c283e104059dae86ea1d670672a80170f27a39529d815843ec9c1f0fa2a03`.
- Probe and fixtures were rebuilt from the immutable Provenance source
  commit `98d5f07f173a9e3f1b365add24b81c934d7e3c61`. The probe was 478,837 bytes
  with SHA-256
  `abbccf45831ef998466542b19169731b9ec4f8a6c3525fce4d7a2c0b5f4b4b43`;
  all 14 fixture hashes matched that source commit's manifest.
- The runner built the offline Paper runtime itself. The archive was
  153,958,528 bytes compressed and 163,396,442 bytes expanded, with SHA-256
  `ba1434cfc3af6fe145660e82f5b07ce9cb46cbc76d23c68a767a3717e7e5ca57`.

The exact source and runtime preparation commands were:

```sh
mkdir -p "$EVIDENCE_ROOT/toolkit-source"
git -C ../provenance archive --format=tar 98d5f07f173a9e3f1b365add24b81c934d7e3c61 | tar -xf - -C "$EVIDENCE_ROOT/toolkit-source"
(cd "$EVIDENCE_ROOT/toolkit-source" && node scripts/run-gradle.mjs :paper-probe:jar safeFixtures hostileFixtures verifySafeFixtureArtifacts verifyHostileFixtureArtifacts)
go run ./cmd/provenance-paper-runtime -paper "$EVIDENCE_ROOT/paper-1.21.8-60.jar" -output "$EVIDENCE_ROOT/paper-prepared-runtime.tar.gz"
```

Every prepared cache entry was SHA-256 verified before staging and was verified
again by `artifact.Cache.AcquireExact` before workspace materialization.

## Sandbox and CLI procedure

The checksum-pinned real smoke test was compiled and executed in a disposable
privileged outer container with a delegated cgroup subtree. The workload under
test used the production OCI spec and ran as UID/GID 65532 inside gVisor:

```sh
go test -c -o "$EVIDENCE_ROOT/gvisor-smoke.test" ./internal/provider/gvisor
PROVENANCE_RUNSC_SMOKE=1 \
PROVENANCE_RUNSC_PATH="$EVIDENCE_ROOT/gvisor/runsc-provenance" \
PROVENANCE_RUNSC_ROOTFS="$EVIDENCE_ROOT/alpine-rootfs" \
"$EVIDENCE_ROOT/gvisor-smoke.test" -test.v -test.run '^TestRunscSmoke$' -test.count=1 -test.timeout=60s
```

Result: `TestRunscSmoke` passed. It confirmed the non-root UID, read-only root,
writable bounded tmpfs mounts, absent Docker socket, default network-none path,
and cleanup through real runsc.

Each live fixture then ran through the public CLI form below. Hostile fixtures
ran one at a time in a fresh disposable outer container and required the trusted
`PROVENANCE_LOCAL_EXECUTE_ALLOW_HOSTILE_FIXTURES=true` opt-in.

```sh
provenance-runner execute "$EVIDENCE_ROOT/jobs/$fixture.json" \
  --complete-log "$EVIDENCE_ROOT/results/$fixture.log.gz" \
  >"$EVIDENCE_ROOT/results/$fixture.json" \
  2>"$EVIDENCE_ROOT/results/$fixture.stderr"
```

The live class allocated 1,000 CPU millis, 2,147,483,648 memory bytes, 128
processes, and 1,073,741,824 disk bytes. Its effective network class was `none`,
with zero connections and zero bandwidth. Benign execution used a 90-second
execution deadline. The enable-hang fixture used 20 seconds; the resource-attack
fixtures used 60 seconds; the network and log fixtures used 90 seconds so cold
Paper startup did not become the observed boundary.

## Benign fixture results

| Fixture | CLI | Classification / code | Wall ms | Events | Raw / captured bytes | Log SHA-256 |
| --- | ---: | --- | ---: | ---: | ---: | --- |
| success | 0 | passed | 64,188 | 21 | 26,471 / 21,000 | `6b6f770d305b6fefc1dcaa4e1cf7fb61d31004ac8cd6048311470901c6d39703` |
| on-load-failure | 1 | workload / `on_load_failure` | 64,505 | 23 | 29,135 / 22,202 | `a3a19f3e5191bf7705d6f0b8afa475e2faa78552dad904893501b08ad13c20b3` |
| on-enable-failure | 1 | workload / `on_enable_failure` | 59,303 | 22 | 29,304 / 22,476 | `8dd71593780ba32d6ca159846d103041ee969c82f1b5e51998d5cd436157b5fe` |
| missing-dependency | 1 | workload / `missing_required_dependency` | 62,329 | 19 | 26,877 / 21,953 | `97d5b5378cef8fefcd3216f2573a780cc6f21c9ea37dc633133a66d50889f98b` |
| command-success | 0 | passed | 63,252 | 29 | 28,276 / 20,879 | `8100f91a49c027bbf652626820b2adb06ddb873564221fb56e42b5bac3a3f62c` |
| command-assertion-failure | 1 | workload / `command_assertion_failure` | 64,679 | 29 | 28,611 / 20,985 | `0dcadaba5742e09147ff6b2edcfe5087d465e74f6f412c865950264e7737e1c9` |

## Hostile fixture results

| Fixture | CLI | Observed containment | Wall ms | Raw / captured bytes | Cleanup |
| --- | ---: | --- | ---: | ---: | --- |
| enable-hang | 1 | `timed_out/job_timeout` at 20-second execution bound | 22,093 | 10,628 / 10,628 | passed |
| process-exit | 1 | workload exit 17 retained | 60,254 | 20,460 / 17,477 | passed |
| memory-bomb | 1 | memory-cgroup kill, workload exit 137 | 59,227 | 22,194 / 18,121 | passed |
| fork-pid-bomb | 1 | PID pressure contained until deadline | 62,158 | 18,566 / 18,566 | passed |
| disk-fill | 1 | bounded tmpfs fill contained until deadline | 62,200 | 45,735 / 45,735 | passed |
| network-scan | 0 | 254 outbound probes under network-none; lifecycle passed | 69,420 | 26,628 / 21,069 | passed |
| metadata-endpoint | 0 | metadata request under network-none; lifecycle passed | 62,165 | 26,424 / 20,805 | passed |
| log-flood | 0 | 3,136,953 bytes observed; 65,536 retained and truncation marked | 64,231 | 3,136,953 / 65,536 | passed |

All 14 final gzip files passed `gzip --test`; each file's SHA-256 and byte count
matched its structured result. The configured test secret was absent from every
JSON result, stderr file, and decompressed complete log.

A deliberate good-fixture run with a 1 GiB memory allocation was also retained
as a negative resource path. It was killed at exit 137, returned a workload
failure, exported a valid complete log, and cleaned successfully. The passing
class above is therefore the evidence-backed Paper allocation for this gate.

## Cleanup and restart evidence

After every pass, workload failure, resource kill, and timeout, the following
checks passed:

```sh
test -z "$(find "$BUNDLE_ROOT" -mindepth 1 -type d -print -quit)"
test -z "$(find "$STATE_ROOT" -mindepth 1 -print -quit)"
test -z "$(find "$WORKSPACE_ROOT" -mindepth 1 -type d -print -quit)"
test -z "$(find /sys/fs/cgroup -maxdepth 1 -type d -name 'provenance-plan03-*' -print -quit)"
! grep -R -F 'PROVENANCE_TEST_SECRET_03' "$EVIDENCE_ROOT/results"
for log in "$EVIDENCE_ROOT"/results/*.log.gz; do
  ! gzip -cd "$log" | grep -Fq 'PROVENANCE_TEST_SECRET_03'
done
```

Unit tests additionally cover cleanup after cancellation, partial preparation,
collection failure, cleanup failure, and startup reconciliation of abandoned
containers and owned workspaces.

## Acceptance mapping

- WP-03A: the generic provider lifecycle and local JSON result path are covered
  by executor tests and all live CLI fixtures. Paper is selected by the generic
  registry; process execution remains an explicitly acknowledged development
  provider and is not a security boundary.
- WP-03B: exact Paper, Java, probe, runtime, target, and dependency hashes and
  declared sizes are enforced before materialization. Cache concurrency,
  redirects, SSRF policy, archive bounds, empty workspaces, minimal config,
  probe, and test-plan construction have focused tests. The live run used the
  catalog Java and prepared runtime.
- WP-03C: OCI tests assert non-root execution, a read-only root, empty
  capabilities, no-new-privileges, isolated namespaces, device deny-by-default,
  cgroup CPU/memory/PID controls, bounded tmpfs disk, and network-none. The real
  smoke and hostile matrix exercise those controls and cleanup. Network-none
  makes the effective connection and bandwidth ceilings zero.
- WP-03D: raw logs and probe events are separated; UTF-8, ANSI, line/total caps,
  redaction, truncation, complete gzip construction, and secure export have
  focused tests. Results report environment identity, wall time, the allocated
  resource class, raw/captured/event/log storage bytes, and truncation state.

The repository verification commands are:

```sh
test -z "$(gofmt -l .)"
go vet ./...
go build -o /tmp/provenance-runner-plan03 ./cmd/provenance-runner
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

All five commands passed; `govulncheck` reported no vulnerabilities. Linux race
tests included the previously failing unprivileged complete-log publication
path. Windows and Darwin amd64 cross-builds also passed, while runtime Paper
initialization now returns an explicit unsupported-platform error outside
linux/amd64. No Protobuf, OpenAPI, or configuration contract changed.

The only known residual trust limitation is unchanged: the target plugin shares
the sandbox JVM and UID with the trusted probe, so probe events are bounded and
validated but not cryptographically attributable. Networked egress policy is
not claimed; this slice intentionally supports only network-none.
