# Measured rootfs boot helper (not yet selected in production)

`scripts/measured-rootfs-boot.py` restores an **already reviewed selection** before
the hosted user runner starts. It does not install or select a generation, stop a
runner, drain the coordinator, edit configuration, enable units, detach loops, or
authorize publication. Keep the signed updater's executable path unchanged:
`/opt/provenance-runner/runner`. Do not combine this layout with the older inactive
generation tool's copied-runner selection.

## Protected installation contract

The future drained selection operation must install and pin both this helper and
its sibling `runtime-generation.py`, the plan, image, manifest and units under
root-owned canonical non-writable ancestry. The helper imports that sibling for
the existing protected-file, hashing and exact-mount primitives. The caller must
pin the helper code itself; the plan does not self-authenticate executable code.
Root and the host kernel are trusted. No shell evaluates plan values.

Version-1 plan fields are exactly:

- `version: 1`, positive integer `uid`, `gid` matching the runtime account.
- `generation`: protected directory named `sha256-<complete image digest>`,
  root:runtime-group mode `0710`. Its ancestors must also permit runtime traversal.
- `image: {path, sha256}`: `<generation>/image.squashfs`, root:runtime-group `0440`,
  one hardlink, bounded to 4 GiB. The whole image is checked on every invocation.
- `imageManifest: {path, sha256}`: `<generation>/image-manifest.json`; must bind
  image bytes, size, actual runtime UID/GID and the accepted two-build record.
- `rootfs`: `<generation>/rootfs`, initially an empty protected directory.
- `loop`: `<generation>/loop`, the managed root:runtime-group `0440` private alias.
- `mountUnit: {path, sha256}`: `/etc/systemd/system/<escaped-rootfs>.mount`.
- `userUnit: {path, sha256}`: `/etc/systemd/user/provenance-runner.service`.

Version 2 additionally binds the selected runtime environment and direct runsc
ELF for the [drained hosted selector](measured-runtime-selection.md). Production
selection uses version 2 so an interrupted environment/hook switch refuses boot;
version 1 remains a mount-only fixture/operator contract.

The mount unit must have exactly the bytes returned by `unit_bytes(plan)`:
SquashFS, `loop,ro,nosuid,nodev`, a 60-second mount timeout and no enablement stanza.
Names are obtained with `systemd-escape --path --suffix=mount`. Paths with systemd
expansion, whitespace, noncanonical components or symlinks are refused. Loaded
unit fragments must match, with no drop-ins or pending daemon reload.

## Boot sequencing

The root wrapper must require the runtime user manager, synchronously run
`python3 <helper> ensure --plan <plan> --plan-sha256 <digest>` before starting the
user runner, and fail closed if it refuses. The user runner remains independently
disabled. Do not add `Before=provenance-runner.service` to a mount synchronously
started from that wrapper's `ExecStartPre`: ordering must not make the mount wait
on its invoking job. Serialize operator starts with the wrapper; the directory
lock coordinates helper invocations, not arbitrary root/systemd actions.

`ensure` requires the user runner inactive/failed and no runtime scopes except
`init.scope`, both before mounting and before changing the private alias. It
starts only the exact mount unit, refuses foreign mounts/nonempty mountpoints,
then checks SquashFS flags, no nested mounts and the loop ioctl's backing inode,
device, full-image mapping and read-only status. Linux `READ_ONLY|AUTOCLEAR` is
accepted alongside `READ_ONLY`; writable, encrypted, offset and size-limited
mappings are rejected.

On reboot, a global loop number can be reused for something unrelated. The
helper never changes that global node or mapping: it atomically replaces only
the proven-owned private alias with the newly verified mount's device number.
An existing `.loop.pending` refuses instead of being adopted/deleted. A failed
mount/start is retained for diagnosis; no timeout triggers forced cleanup.

`verify` is read-only and can run while the runner is active. It rechecks the
image and loaded mount unit, exact mapping and private alias. It does **not**
assert that the running runner has selected this rootfs, that its executable is
measured, or that gateway/terminal evidence is correct.

## Evidence and remaining work

Unit tests exercise refusal, idempotence, private-alias replacement and failure
paths. `test-measured-rootfs-boot-fixture.sh` uses a fresh networkless privileged
systemd guest with synthetic SquashFS bytes: real mount/ioctl verification,
runtime-user read access, active-runner refusal, remount, stale alias repair and
preservation of a separately allocated unrelated loop. It verifies owned loop
and mount absence before successful container removal. Failed guests are stopped
and retained. This is not a hostile-plugin fixture or a real image build proof.

The fixture then enables a synthetic root wrapper, restarts only its private
container, observes a fresh PID 1 and empty `/run`, and requires successful
mount-helper-before-user-runner startup. It verifies the active mapping again,
stops the wrapper and mount, and proves owned loop absence. This exercises real
systemd cold-start ordering, not a host-kernel reboot or the signed updater. The
fixture explicitly configures the user manager's unit search path to match the
hosted fragment path; the helper does not accept Ubuntu's alternate XDG alias.

Still required: production host boot/reboot acceptance, reviewed drained selection and
rollback, fixed-path signed updater integration, measured Paper-to-terminal
identity and restart/replay/cleanup acceptance. Passing this helper's tests does
not complete those gates or authorize unattended production activation.
