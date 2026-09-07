#!/usr/bin/env bash
# Disposable container fixture ONLY. Never mount the installed runner rootfs.
set -euo pipefail
[[ $(id -u) == 0 && -f /.dockerenv ]]
fixture_uid=${PROVENANCE_MEASUREMENT_FIXTURE_UID:-1000}
fixture_gid=${PROVENANCE_MEASUREMENT_FIXTURE_GID:-1000}
[[ "$fixture_uid" == 1000 || "$fixture_uid" =~ ^6[0-3][0-9]{3}$ ]]
[[ "$fixture_gid" =~ ^[1-9][0-9]*$ ]]
fixture=/tmp/provenance-runtime-fixture
[[ ! -e "$fixture" ]]
mkdir -m 0711 "$fixture"
mkdir -m 0711 "$fixture/source" "$fixture/mount"
chown "$fixture_uid:$fixture_gid" "$fixture/source"
mkdir -m 0700 "$fixture/work"
chown "$fixture_uid:$fixture_gid" "$fixture/work"
loop=
cleanup() {
  if mountpoint -q "$fixture/mount"; then umount "$fixture/mount"; fi
  if [[ -n "$loop" ]]; then
    [[ $(losetup --noheadings --output BACK-FILE "$loop") == "$fixture/image.squashfs" ]] || return 1
    losetup --detach "$loop"
  fi
}
trap cleanup EXIT
cp /tmp/runtimeidentity.test "$fixture/source/fixture-test"
chmod 0555 "$fixture/source/fixture-test"
touch "$fixture/source/private-root-file"
chmod 0600 "$fixture/source/private-root-file"
/tmp/mksquashfs "$fixture/source" "$fixture/image.squashfs" -noappend -no-recovery -processors 1 -mkfs-time 0 -all-time 0 >/dev/null
chmod 0444 "$fixture/image.squashfs"
cp "$fixture/image.squashfs" "$fixture/wrong-inode.squashfs"
chmod 0444 "$fixture/wrong-inode.squashfs"
cp "$fixture/image.squashfs" "$fixture/writable.squashfs"
chmod 0664 "$fixture/writable.squashfs"
cp /tmp/runsc "$fixture/runsc"
if [[ -d /tmp/gvisor-bin && ! -L /tmp/gvisor-bin ]]; then cp -a /tmp/gvisor-bin "$fixture/gvisor-bin"; fi
chmod 0555 "$fixture/runsc"
ln -s runsc "$fixture/runsc-link"
# Loop allocation is host-global even inside this private mount namespace.
# Only create the device node named by the kernel free-device query and let
# losetup perform allocation. Never detach a pre-existing mapping.
for attempt in {1..8}; do
  free=$(losetup --find)
  free=${free% (lost)}
  [[ "$free" =~ ^/dev/loop([0-9]+)$ ]]
  minor=${BASH_REMATCH[1]}
  [[ -e "$free" ]] || mknod "$free" b 7 "$minor"
  if loop=$(losetup --find --show --read-only "$fixture/image.squashfs"); then break; fi
done
[[ "$loop" =~ ^/dev/loop[0-9]+$ ]]
[[ $(losetup --noheadings --output BACK-FILE "$loop") == "$fixture/image.squashfs" ]]
# This device node is private to this disposable container filesystem; only
# read access is needed for status ioctls. No host device node mode is changed.
chmod 0444 "$loop"
mount -t squashfs -o ro,nosuid,nodev "$loop" "$fixture/mount"
setpriv --reuid "$fixture_uid" --regid "$fixture_gid" --clear-groups env PROVENANCE_MEASUREMENT_FIXTURE_ROOT="$fixture" /tmp/runtimeidentity.test -test.run '^TestRuntimeMountFixture$' -test.v -test.count=1
if [[ -f /tmp/gvisor-preflight.test ]]; then
  setpriv --reuid "$fixture_uid" --regid "$fixture_gid" --clear-groups env PROVENANCE_MEASUREMENT_FIXTURE_ROOT="$fixture" /tmp/gvisor-preflight.test -test.run '^TestMeasuredPreflightWithProtectedImageFiles$' -test.v -test.count=1
fi
