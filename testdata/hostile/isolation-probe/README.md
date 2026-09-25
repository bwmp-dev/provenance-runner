# Isolation probe fixture (hostile)

A Paper plugin that, when run inside a sandboxed job, actively attempts the
escapes an untrusted plugin would try and prints a structured `PROBE <name>
PASS|REACHED` line per attempt. `PASS` means isolation held; `REACHED` is a
containment failure. The Plan 03 exit gate requires every probe to report
`PASS`.

Attempts: PostgreSQL (5432) and Temporal (7233) on private/management
addresses, the Coolify management host (`10.0.0.1:8000`/`:443`), cloud metadata
(`169.254.169.254`, `169.254.170.2`), Docker/containerd sockets, host PID and
network namespace access (`/proc/1/ns`, `/proc/1/root`), sibling job directory
reads, and environment credential scraping.

## Do not run against production

This fixture only targets well-known private and metadata addresses, and only
from inside a `network=none` gVisor sandbox where no packet can leave the guest.
It is inert unless the Paper process property
`-Dprovenance.fixture.hostile.enabled=true` is set, and must run only inside a
disposable, resource-limited Plan 03 runner. See the runner `AGENTS.md`:
"Hostile fixture tests run only in an explicitly prepared disposable Linux
environment."

## Build

The fixture follows the same convention as the pinned toolkit fixtures under
`packages/test-fixtures/hostile/` in `bwmp-dev/provenance` (a `JavaPlugin`
subclass with a `requireOptIn()` guard, compiled against `paper-api-stubs`).
Build it there, or standalone against a Paper/Bukkit API jar:

```sh
# Standalone: compile against any Paper API jar, then package with plugin.yml.
javac -cp paper-api.jar -d build/classes \
  src/main/java/dev/provenance/fixtures/hostile/IsolationProbePlugin.java
cp src/main/resources/plugin.yml build/classes/
( cd build/classes && jar --create --file ../isolation-probe-1.0.0.jar . )
```

To run it through the real runner, register it as a Plan 03-style fixture
(a `provider: "paper"` local job whose `target` points at the built jar with
its SHA-256/size) and drive it with `scripts/hostile-fixtures.sh` on a prepared
gVisor host. The shell-only equivalent, which needs no Paper download, is
`TestIsolationProbeSandboxDeniesEscapes` in
`internal/provider/gvisor/isolation_probe_linux_test.go`.

## Shared attack surface

The Java probe and the shell probe assert the identical target list, so the two
forms stay in lockstep. See `docs/security/hostile-fixture-inventory.md`.
