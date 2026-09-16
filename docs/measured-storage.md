# Bounded persistent measured storage

`scripts/measured-storage.py` verifies and restores one **already provisioned**
dedicated ext4 filesystem inside a fully allocated, fixed-size backing file.
This limits persistent staged inputs, bundles and recovery journals independently
of free space on the host root filesystem. Guest workspace/tmpfs limits remain
separate. Shared filesystem exhaustion can refuse subsequent jobs; this is a
host staging bound, not a per-job quota or a guarantee of available capacity.

The helper never creates/formats a backing file, resizes a filesystem, edits
units, starts a runner, detaches loops, deletes data or changes network policy.
`ensure` starts only the pinned mount unit; `verify` mounts nothing. Installation
is a separate guarded operator operation. It must exclusively create a new file,
fully allocate it before formatting, use `nodiscard` when formatting, and retain
the resulting identity. Never format an existing path on retry. An interrupted
provisioning operation needs inspection, not automatic recreation.

The pinned root-protected JSON plan has exactly:

- `version: 1`.
- `backing: {path,device,inode,sizeBytes,blockBytes,inodes,uuid}`.
- `mountpoint`, a canonical protected path outside the backing file.
- `mountUnit: {path,sha256}`, the exact systemd-escaped mount unit.

The file must be root:root `0600`, regular, single-link and fully allocated.
Size is 64 MiB–16 GiB, filesystem blocks are 1024/2048/4096 bytes, and inode count
is 1024–1048576. The ext4 superblock's complete 64-bit capacity, inode count and
UUID must match the plan. It must have a journal and extents. Mutable data is
deliberately **not** represented by an immutable content hash: custody, fixed
device/inode, filesystem geometry and actual loop backing are checked instead.
Root/kernel remain trusted. Do not enable discard or run trim on the backing
filesystem; loss of full allocation refuses subsequent verification.

Generate the unit using `unit_bytes(plan)`. It mounts ext4 with
`loop,rw,nosuid,nodev,noexec`. Both the empty underlying mountpoint and mounted
filesystem root are root:root `0711`. Prepare the filesystem root mode during
initial provisioning, not by relaxing permissions after a failed verification.
Plan/unit/backing must remain outside the managed mount. Loaded metadata must
match the pinned fragment with no drop-ins or pending reload. Starting an inactive
unit refuses a foreign mount or nonempty mountpoint. Verification checks the
actual loop file device/inode, read-write/autoclear flags, zero offset/size limit,
mount device/options, filesystem capacity and absence of nested mounts. No global
loop aliases are changed. An exclusive backing-file lock serializes this helper.

Install the helper alongside protected `measured-rootfs-boot.py` and
`runtime-generation.py`; the installing coordinator pins all three scripts.
Invoke as root with isolated Python, using `ensure` or `verify`:

```text
python3 -I /opt/provenance-runner/measured-storage.py ensure \
  --plan <protected-storage-plan> --plan-sha256 <sha256>
```

The daemon's persistent bundle and journal directories must be provisioned on
this mount with their required individual custody. Secret storage remains a
separate bounded tmpfs. A service wrapper must verify storage before opening the
daemon, and stop admission if storage is lost; this helper alone does not wire
those dependencies or authorize activation. An 8 GiB production allocation is
the intended initial bound, subject to the configured maximum input/job sizes.

## Acceptance

The disposable networkless systemd guest uses a newly created 64 MiB file. It
exercises actual byte and inode exhaustion, refuses backing/UUID/size/mode drift,
rejects a nonempty mountpoint, checks backing-lock exclusion and idempotence,
then restarts the guest's system manager. Reopening the mount preserves an
fsynced marker. Exact owned mount and loop absence are verified on cleanup.
Unit tests cover geometry including high block bits, unsupported filesystems,
mount-only unit rendering, read-only verification behavior and unsafe starts.

This is not a physical host reboot, production provisioning, filesystem crash
consistency proof, measured daemon composition test or alpha release acceptance.
Those gates remain separate. The composed measured fixture now remounts only its
container-private staging bind with `nosuid,nodev,noexec` and checks those flags
before execution. Real Paper 1.21.8/build 60 with the actual gateway client and
late test secrets passed three repetitions with these flags on 2026-09-16:
service binary `b28def503e2a86208e3107d5f4bfb8828e940e26d30e952038cb497798b4b6f2`,
worker binary `72cb4ae4145bf0788c3babeeee2d1f0bdcf1e5eb0c00ab91a48eb8103e7e72e2`.
Terminal acknowledgement, raw/base64 live/archive redaction and owned retirement
passed; real platform DB/object-storage acceptance was not part of this fixture.
The first attempt refused before any runtime resource creation because BusyBox
requires both source and target for bind remount. Supplying both and checking
`statvfs` mount flags corrected the fixture; no mount protection was removed.
This proves noexec compatibility separately from the ext4 capacity/restart test,
not a combined production filesystem/daemon acceptance claim.
