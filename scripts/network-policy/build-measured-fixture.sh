#!/usr/bin/env bash
# Fresh disposable builder only. All inputs are synthetic fixture assets.
set -euo pipefail
[[ $(id -u) == 0 && -f /.dockerenv && $# == 3 ]]
[[ ! -e /tmp/measured-route-source && ! -e "$3/image.squashfs" ]]
mkdir -m 0755 /tmp/measured-route-source
cp "$1" /tmp/measured-route-source/smoke
chmod 0555 /tmp/measured-route-source/smoke
chown 65532:65532 /tmp/measured-route-source
LD_LIBRARY_PATH="$2/lib" "$2/mksquashfs" /tmp/measured-route-source "$3/image.squashfs" \
  -noappend -no-recovery -processors 1 -mkfs-time 0 -all-time 0 >/dev/null
chmod 0444 "$3/image.squashfs"
