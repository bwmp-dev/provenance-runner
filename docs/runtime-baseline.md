# Inactive first-install runner baseline

`scripts/runtime-baseline.py` exclusively creates a reviewed first-install system
service baseline. It never starts, restarts, enables, stops or kills anything.
Its only manager mutation is a real system-manager `daemon-reload`. It neither
downloads artifacts nor changes mounts, AppArmor, sysctls, network policy or
credentials in existing installations. This package does not replace the
accepted [runtime generation operator](runtime-generation.md).

This is inactive provisioning, **not runner loader, credential issuance,
cryptographic identity, hosted Paper or production acceptance**. The installer
checks protected input bytes and credential-reference bindings. The existing
runner loader remains responsible for complete identity-document/key validation
at separately authorized activation. It never invokes the supplied runner to
validate a document. Synthetic fixture credentials are deliberately unusable.
No remote drain truth is inferred from local process absence.

## Reviewed plan

All inputs, including plan, must be canonical absolute regular files with
root-protected ancestry: root ownership, no symlinks, special privilege bits,
group/other write access or hardlinks. JSON documents are at most 64 KiB, reject
duplicate and unsupported fields, and are parsed as data. Private input files
must be mode `0400` or `0600`; ELF inputs must be executable and at most 512 MiB.
Never source documents or publish their contents. Retain hashes privately with
the exact approved operator inputs.

The version-1 plan has exactly these fields:

| Field | Meaning |
| --- | --- |
| `version` | Integer `1` |
| `uid`, `gid` | Explicit existing nonroot runtime UID and its primary GID |
| `destination` | New root-owned directory for executable, environment and ownership ledger |
| `stateDirectory` | New runtime-owned private directory for connect configuration, credential, identity and future sidecar journal |
| `unitDestination` | New `/etc/systemd/system/provenance-runner.service` or `provenance-runner-<suffix>.service` |
| `runner` | `{path,sha256}` pin for the direct runner ELF |
| `environment`, `unit`, `connect`, `credential`, `identity` | `{path,sha256}` pins for the exact private source bytes to copy |
| `runtime` | `{path,sha256}` pin for the private approved prerequisite document below |

The three destinations must be distinct and nonoverlapping beneath existing
protected parents. No destination is adopted, repaired or overwritten. No process
may belong to the explicit runtime UID; the installer only observes and refuses,
never stops a process or user manager. Missing UID/GID authority is refusal.

The strict version-1 runtime document has exactly `version`, `runsc`,
`legacyRootfs`, `environment` and `downloads`. `runsc` is a protected direct ELF
`{path,sha256}` reference which the runtime UID/GID can execute. `legacyRootfs`
is `{path,treeSha256}`: an existing root-owned exact read-only mount under
protected ancestry, with no nested mounts. Its tree digest uses the same
normalized GNU-tar definition as the accepted generation tool. The installer
does not mount, remount, prepare or adopt this tree.

`environment` is the complete parsed environment map, which must exactly equal
the pinned environment file. The supported allowlist is `ENV_NAMES` in the tool;
unknown assignments (including database, Temporal, marketplace, management and
dynamic-loader variables) fail. Values may be unquoted without whitespace, or
single-quoted without escapes. There is no shell expansion. The runsc/rootfs
paths and `sha256:<tree digest>` root identity must match the prerequisite pins.

`downloads` contains exactly the `PROVENANCE_PAPER_PROBE` and
`PROVENANCE_PAPER_PREPARED_RUNTIME` pin objects, each with `prefix`, `uri`,
`sha256` and positive `sizeBytes`. Each URI/hash/size must match its environment
assignment. URIs must be HTTPS without credentials, queries or fragments.
The prepared-runtime expansion bound and artifact host allowlist are required.
These are approved future download references; no download occurs and the tool
does not claim that synthetic pins satisfy the compiled Paper catalog.

This first version supports the existing **single prepared-runtime environment
composition**. `PROVENANCE_PAPER_PREPARED_RUNTIMES`, measured generation inputs,
user units, custom commands/hooks and arbitrary system-unit composition are
explicit refusals. No production profile, image, probe or download pin is chosen
by this package. The existing workspace, cache, gVisor state and bundle roots
must be distinct, protected-parent directories owned by the stated UID/GID with
mode `0700`; these approved runtime prerequisites are inspected, never changed.

The connect document keeps the existing
`provenance.runner-connect/v1alpha1` field names and organization scope. Its
credential and identity paths must be `credential` and `identity.json`, or the
equivalent absolute paths in `stateDirectory`. The pinned identity reference
must be active and bind the connect runner/organization IDs and credential hash.
No key generation or enrollment request occurs. Full key validation and live
credential validity are outside this inactive prerequisite.

## Unit and writable state

The source unit must equal the following bytes, substituting only the explicit
plan values (including the final newline). This narrow composition permits no
shell, specifier expansion, extra environment injection or activation hooks.

```ini
[Unit]
Description=Provenance inactive runner baseline

[Service]
Type=simple
User=<uid>
Group=<gid>
ExecStart=<destination>/runner connect <stateDirectory>/connect.json
EnvironmentFile=<destination>/runner.env
Restart=no
NoNewPrivileges=yes
UMask=0077

[Install]
WantedBy=multi-user.target
```

The installed executable is root-owned `0555`, environment and unit root-owned
`0600`, and executable/environment directory root-owned `0755`. The separate
state directory is runtime-owned `0700`, with runtime-owned `0600` connect,
credential and identity files. This preserves the accepted journal location
beside the connect configuration and directory-level enrollment/rotation atomics.
The runtime identity can replace files within its private state directory;
baseline repeat/verification detects that drift and refuses. It does not freeze
state with root ownership or invent a journal path incompatible with the loader.

## Operations and interrupted state

Under separately approved operator authority, use:

```text
python3 scripts/runtime-baseline.py install --plan /protected/plan.json --plan-sha256 <digest>
python3 scripts/runtime-baseline.py verify --plan /protected/plan.json --plan-sha256 <digest>
python3 scripts/runtime-baseline.py recover --plan /protected/plan.json --plan-sha256 <digest>
```

There is no production invocation implied by these examples. `install` requires
an absent service, absent destinations, no pending fragments/aliases/drop-ins or
enablement links, and a disabled, stopped manager view. All creations are
exclusive. An existing protected parent is locked without creating or adopting
a lockfile. A private append-only ownership ledger records the plan hash and
exact device/inode/type/owner/mode and byte hash of each created object.

After copying, the real manager reload must report the exact loaded fragment,
numeric User/Group, single ExecStart and required EnvironmentFile, no inline
environment or drop-ins, no pending reload, and disabled/inactive/dead with zero
main/control PID. Only then is completion durably recorded. An exact repeat
verifies all identities and returns without reloading or modifying anything.

`recover` is a read-only ownership inspection. It reports retained, exactly
recorded objects and completion status; it never resumes, removes or rolls back
an installation. Missing/partial journals, unrecorded creations, foreign files,
changed inodes and changed bytes refuse with retained state. An interruption
after the completion record itself was fsynced may be an exact completed repeat.
Other incomplete installations cannot be reused: resolve retained objects under
separate exact operator review. No command claims successful deletion or drain.

## Disposable real-systemd proof

Build the fixture-only Dockerfile and pass its exact local image ID to
`bash scripts/test-runtime-baseline-fixture.sh sha256:<image-id>`. The harness
creates an exclusive Docker guest with a real PID-1 systemd, private PID/cgroup/
mount namespaces, network disabled and no host binds. The guest is privileged
only to provide its own system-manager cgroup and read-only fixture mount setup;
it never mutates shared host services or security policy. Do not run the Python
fixture directly on a host. Missing real-systemd prerequisites are failure, not a
fake-manager fallback. Fixture tooling package versions are not production pins.

The fixture uses a pinned harmless ELF, synthetic identities and configuration,
then proves first install, unchanged exact repeat, real loaded-manager identity,
disabled/stopped state, sidecar atomics, inode drift, foreign files/fragments/
drop-ins, enabled/active refusal, unsafe paths, secret permissions, forbidden
environment keys, nine reached durability interruptions and interruption after
a real reload. It retains plan/runtime/runner/environment/unit input hashes and
actual outcomes, checks foreign work survives refusal, removes only exact owned
unit inodes, reloads and observes their absence, and removes fixture mounts and
identity. The outer harness stops and removes only its exact labeled container,
then freshly verifies absence. Remaining private guest files disappear with that
container; no broad host cleanup occurs. No hostile JAR or full Paper gate runs.

Live installation still needs separately approved exact production inputs,
operator privilege and actual remote drain evidence. This package does not
complete WP-10A, WP-11E, or an alpha gate.
