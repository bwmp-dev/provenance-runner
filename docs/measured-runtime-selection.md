# Drained hosted measured runtime selection

`scripts/measured-runtime-selection.py` changes only the hosted `runner.env` and
`verify-rootfs` hook. It never starts/stops a runner, changes its executable or
user unit, alters credentials, drains the coordinator, or installs AppArmor
policy. Initial artifact installation and privileged approval are separate.
Use only after exact-head and post-main acceptance; no production activation is
claimed by the synthetic fixture.

## Inputs and preparation

Install protected pinned `measured-rootfs-boot.py` and `runtime-generation.py` as
siblings in `/opt/provenance-runner`, plus the pinned selector. Install the image,
manifest, generation directories and exact mount unit using the boot-helper
contract. Reload mount-unit metadata, without starting it. The runner binary
stays `/opt/provenance-runner/runner`; runsc must be the pinned direct ELF at
`/opt/provenance-runner/runsc`, not the legacy shell wrapper.

The immutable **version-2 boot plan** adds these fields to version 1:

- `runtimeEnvironment: /opt/provenance-runner/runner.env`.
- `runsc: {path, sha256}` for the direct ELF.

Version 2 verifies the seven owned runtime settings before mounting at startup:
runsc, rootfs, image identity, embedded-executable mode, systemd-user driver,
image path and private loop alias. It deliberately does not pin unrelated
catalog values across future signed catalog updates. The environment must be
root:runtime-group `0640`, single-link, at most 512 KiB. Each assignment must be a
complete uppercase-key line with a JSON-quoted string or narrow plain value.
Duplicate assignments, continuations, multiline quoting, CRLF, missing final
newline and ambiguous syntax refuse. This is not a general shell/systemd parser.

The version-1 **selection plan** contains exactly:

- `version: 1`.
- `{path,sha256}` pins named `bootPlan`, `helper`, `generationHelper`, `runner`,
  `wrapper`, `updater`, `environmentBefore`, `environmentAfter`, `hookBefore`.
- `legacyRootfs: {path,treeSha256}` for `/opt/provenance-runner/rootfs`.

The root wrapper and updater unit paths are respectively
`/etc/systemd/system/provenance-runner.service` and
`/etc/systemd/system/provenance-runner-updater.service`. They must be the exact
loaded fragments without drop-ins or pending reload. The unchanged user unit is
pinned by the boot plan. Snapshot files are separate root-owned `0600` single-link
files, never live targets. They may contain private configuration: never publish
their contents. Store only hashes in public evidence.

Generate `environmentAfter` with `render_environment(bootPlan, beforeBytes)` from
the boot module. It preserves every unrelated line verbatim and replaces only
the seven runtime settings. The before snapshot must select the expected legacy
tree, legacy runsc wrapper and systemd-user driver, without measured settings.
The new hook is generated from the pinned boot helper and boot-plan digest.
The selector itself and helper code must be pinned by the installing coordinator;
the plan is not a self-authenticating executable.

## Drain and selection

The authorized coordinator keeps admission disabled for this runner throughout
the operation and establishes no active leases or pending terminal replay. Its
separate root-protected, hash-pinned drain document contains `version:1`, the
selection `planSha256`, integer `issuedAt`/`expiresAt` (at most five minutes),
`platformDrainEvidenceSha256`, `activeLeases:0`, `pendingTerminalReplay:0`.
The local tool checks binding/freshness, not the truth or authorization of remote
evidence. A synthetic fixture document never substitutes for a live drain.

Stop the root wrapper and updater through the separately authorized operation;
both must remain inactive/failed, and the user runner and sandbox scopes must be
quiet. The updater's existing lifetime lock is held exclusively for the entire
selection. Both updater journals must be absent or complete; the worker-owned
local journal must have no active job, terminal message or credential rotation.
The generation directory lock excludes concurrent mount-helper invocations.

Invoke as root with isolated Python:

```text
python3 -I /opt/provenance-runner/measured-runtime-selection.py select \
  --plan <selection-plan> --plan-sha256 <digest> \
  --drain <fresh-drain> --drain-sha256 <digest>
```

Only three exact byte-pair states are accepted: old environment/old hook,
old environment/new hook, and new environment/new hook. Selection changes the
hook first. If interrupted there, the environment-bound new hook refuses startup.
It then installs the reviewed environment and verifies/ensures the measured
mount. The original runner remains stopped. A mount failure leaves the selected
bytes for inspection, not an invented rollback success.

`rollback` uses the same pinned plan and a **fresh** drain. It restores the
environment first, then the old hook. Its intermediate state also refuses boot.
The exact retained legacy tree must still be mounted read-only and hash-match
before either transition; the selector never silently reprovisions it. Atomic
replacement reuses the accepted durability/ownership and exact-retry primitive.
Credentials, binary, user unit, and unrelated environment bytes are untouched.

Rollback retains the measured generation and mount for diagnosis. It neither
force-detaches a loop nor claims full resource disposal. After verified rollback,
the operator may separately stop the exact proven mount unit and check loop
absence. Later catalog changes cause the original full-environment selection
plan to refuse: prepare a new reviewed snapshot/plan, not a silent reversion of
new catalog configuration. Starts, signed-update testing, cleanup and resuming
admission remain explicit coordinator steps.

## Evidence and remaining acceptance

Unit tests cover grammar, preservation, drain refusal, ordering and interrupted
replacement retry. The networkless privileged guest fixture invokes the real
CLI with actual protected plans, loaded units, locks, worker journal, read-only
legacy bind mount and measured SquashFS loop. It proves updater-lock exclusion,
mixed-state boot refusal, selection/idempotence, active-runner rollback refusal,
exact original-byte restoration and unchanged fixed binary/user-unit hashes.
It also refuses pending updater operations/terminal replay and proves that a new
catalog can pass the runtime boot binding while the old full-snapshot rollback
plan refuses to erase that catalog change.
It verifies owned mount/loop absence during fixture cleanup. The fake runsc ELF,
catalog and coordinator drain are explicitly synthetic.

Live acceptance still requires actual coordinator drain, reviewed host artifact
installation and any exact AppArmor attachment, measured Paper execution through
terminal/platform evidence, fixed-path signed update/rollback, reboot, replay,
resource limits and cleanup. This package does not authorize a public release or
claim signing/verification readiness.
