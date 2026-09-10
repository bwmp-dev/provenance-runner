# Inactive measured runtime generations

This operator package never starts, restarts or enables a service. It does not
change AppArmor, sysctls, the legacy rootfs installer, remote gateway state or
credentials. Production use requires separate exact-pin review and explicit
privileged approval. A successful installation is not hosted Paper acceptance.

## Source and build

Use the exact Ubuntu OCI image and export/prepare recipe in
`.github/workflows/plan03-acceptance.yml`. Its normalized prepared tree must be
`55b3d6002a16c74e9f37638a451a4b4c32b4078b06377d85a8633b89c2506500`.
Never source an image from a copy of the live runtime. The fixture driver exports
the pinned stopped container and operates on a new disposable tree only.

`prepare-ubuntu-measured-source.py` verifies that read-only tree before and after
producing a **new** normalized archive. Its narrow transformation excludes only
the verified empty `dev/console`, `dev/shm` and probe-event placeholder, and
dereferences the two exact accepted regular hardlink pairs. The common measured
builder recreates the event placeholder and runtime mount targets. Unused empty
console/shared-memory placeholders are omitted; no runtime claim depends on
them. Unknown hardlinks, special objects and nonempty placeholders fail.
The generic safe archive extractor is unchanged. Existing accepted preparation
removes privilege-bearing modes; this adapter does not introduce new mode rules.

Retain its source OCI/tree/archive record, then use the accepted private pinned
builder and `build-measured-rootfs.py` with the actual runtime UID/GID. The builder
creates two independently staged images and requires identical complete bytes.
Retain its manifest and hash it. The host loader/glibc remain prerequisites, not
a hermetic toolchain claim. Paper/JDK acquisition remains the separately pinned
accepted catalog; neither the Ubuntu image nor the Alpine smoke substitutes for
actual Paper execution.

## Reviewed operator inputs

All input files and their ancestry must be root-owned, canonical, non-symlink and
not group/other writable. Keep plan, old/new environment and unit bytes private;
public evidence should contain hashes only. No shell evaluates these documents.

The strict version-1 plan contains:

- `generation`: a new protected-parent destination named `sha256-<image digest>`.
- Positive integer `uid` and `gid`.
- `{path,sha256}` pairs for `runner`, `currentRunner`, `runsc`, `image`,
  `imageManifest`, `currentConfig`, `newConfig`, `unit`, and `newUnit`.
- `legacyRootfs: {path,treeSha256}` identifying the retained read-only legacy tree.

Runner and runsc inputs must be direct ELF files. The image manifest must match
the image digest, UID/GID and two-build proof. The old runner remains at its
protected, pinned location for rollback. The installed generation copies the new
runner, direct runsc and image without replacing existing files.

The new environment may change only the established runtime variables selected
by the tool: `PROVENANCE_RUNSC_PATH`, `PROVENANCE_ROOTFS`,
`PROVENANCE_ROOTFS_IDENTITY`, `PROVENANCE_MEASURED_ROOTFS_IMAGE`,
`PROVENANCE_MEASURED_LOOP_DEVICE`, `PROVENANCE_MEASURED_RUNTIME_MODE` and
`PROVENANCE_GVISOR_CGROUP_DRIVER`. Paths point into the exact generation; the
mode is `embedded-executable` and driver is `systemd-user`. Unrelated bytes are
preserved exactly. Duplicate or shell-escaped owned assignments are unsupported.

The new unit may change only the single unescaped absolute `ExecStart` binary
path, from the pinned old runner to the new generation runner. Arguments and all
other bytes remain unchanged. It must contain exactly the reviewed
`EnvironmentFile=<currentConfig path>` directive. The loaded unit must have the
exact fragment path, no drop-ins and explicit matching runtime User/Group.
Ambiguous/multi-command units and user-unit deployment composition are not
automatically converted. No unrelated unit is edited.

The coordinator separately supplies a root-protected, hash-pinned drain record:
`{version:1,planSha256,issuedAt,expiresAt,platformDrainEvidenceSha256,
activeLeases:0,pendingTerminalReplay:0}`. Times are integer Unix seconds, with at
most five minutes between issue and expiry. The digest links actual authorized
control-plane drain/replay evidence; **this tool does not establish its truth**.
The coordinator must keep remote admission disabled throughout selection or
rollback. Local process absence is never substituted for remote drain evidence.
The named service and runtime user manager must be stopped, and no runtime-UID
process may remain. Stop those only through the separately approved operation;
the script never kills processes.

## Operations

Invoke `python3 scripts/runtime-generation.py <action> --plan <file>
--plan-sha256 <digest> --drain <file> --drain-sha256 <digest>` as the authorized
root operator. No installation command is implied for the production host.

- `install`: exclusively create/mount a new generation. A private read-only loop
  node grants only the requested runtime group access; global device-node modes
  are never changed. Installation does not select configuration.
- `verify`: verify copied object device/inode/digests, exact SquashFS mount,
  loop backing inode/device/offset/size/read-only state and private node modes.
- `select`: verify the generation, replace the explicitly pinned environment and
  owned unit with the reviewed pair, then reload unit metadata when necessary.
  It never starts the service. A crash between replacements is recoverable only
  from the exact old/new pair; a third identity is rejected.
- `rollback`: with fresh drain evidence, restore exact old environment/unit
  bytes, reload metadata when necessary and detach only the proven owned mount
  and loop. Busy or aliased resources refuse, never force/lazy unmount.
- `recover`: for an incomplete, **unselected** generation, prove the journal and
  exact owned image/mappings before detaching. It retains files and a detached
  marker; it never silently resumes or adopts incomplete installation.

Generation bytes and backups remain after rollback/recovery for inspection.
Reinstallation over an incomplete or detached generation is intentionally
refused. Choose a reviewed new protected parent, not deletion/reset of old state.
No systemd mount unit is installed: a reboot invalidates the loop/mount identity,
and verification fails closed until separately reviewed reprovisioning. Do not
enable the service for unattended startup using this temporary alpha generation.

The separate [measured rootfs boot helper](measured-rootfs-boot.md) introduces a
mount-only layout compatible with the hosted user-manager wrapper and fixed-path
signed updater. It is not an automatic upgrade or selector for these inactive
generations; production selection and reboot acceptance remain separate gates.

## Acceptance and remaining gate

On restricted-userns CI hosts, the synthetic retained-root guest executes inside
the already-approved measured-systemd fixture lifetime. It reuses that fixture's
exclusive fresh UID/GID and exact protected `gvisor-smoke.test` attachment, mounted
read-only at the same absolute path in the disposable container. Host-before,
container-before/after and host-after records require identical device, inode,
hash, owner and mode. No new profile rule or attachment is loaded. The original
cgroup monitor finishes before this sequential guest proof; the container must
stop before the existing zero-owned-process profile removal. Failed containers
remain stopped for diagnosis, never intentionally running with the profile.

`test-runtime-generation-ci.sh` runs bounded disposable-container source/image
proof, real loop/mount/install/refusal/rollback tests and the previously skipped
protected runtime tests. Its systemd reload calls are explicitly simulated; the
existing separate measured-systemd smoke still proves actual launcher scopes.
Unit tests cover exact environment/unit deltas and stale/foreign/incomplete drain
refusal. No full Paper gate is dispatched by this package's normal CI.

The operator-entrypoint fixture additionally invokes the actual command-line
parser, protected plan/manifest loading, generation lock, both drain checks and
legacy-tree hashing against real disposable files and read-only bind mounts.
Its exclusive container-local `systemctl` fake models loaded unit identity and
`NeedDaemonReload`; it is not a real manager or an assertion of production drain.
The fault matrix records each reached injection, owned recovery versus retained
pre-allocation incomplete files, and observed loop/mount absence. Cleanup success
is emitted only after explicit cleanup and fresh observations, not a literal flag.
Early unjournalled/partial copies are retained rather than adopted automatically.

Replacement files start private and explicitly regain the original mode after
ownership is set, before atomic publication; the operator umask cannot remove
required group-read or executable permissions. Unit tests cover masks022/077/0777
and exact ownership/mode preservation. The disposable systemd selector fixture
runs both selection and rollback with umask077 and checks0755 hooks/0640 config.

Replacement-file tests cover partial write, flush, fsync, chmod and ownership failures,
exact retry, pre-existing/substituted temporary files, and a directory-sync failure
after atomic replacement. Only the exact exclusively created temporary inode may
be removed on pre-replacement failure; successful replacement is never silently
undone when the following directory sync fails. General installation-journal
retention behavior is unchanged.

After implementation acceptance, the real hosted gate still needs approved
drained installation, any separately approved exact AppArmor attachment, actual
Paper execution with measured provider-to-terminal-to-platform identity,
resource limits, cancellation, restart/lost-ack replay and cleanup. These scripts
do not authorize signing, key custody or a public verification claim.
