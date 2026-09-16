#!/usr/bin/env bash
# Fresh disposable builder only. All inputs are synthetic fixture assets.
set -euo pipefail
[[ $(id -u) == 0 && -f /.dockerenv && $# == 3 ]]
[[ ! -e /tmp/measured-route-source && ! -e "$3/image.squashfs" ]]
mkdir -m 0755 /tmp/measured-route-source
cp "$1" /tmp/measured-route-source/smoke
cp "$3/paper-helper" /tmp/measured-route-source/provenance-measured-paper
chmod 0555 /tmp/measured-route-source/provenance-measured-paper
chmod 0555 /tmp/measured-route-source/smoke
chown 65532:65532 /tmp/measured-route-source
mkdir -p /tmp/measured-route-source/{proc,dev/pts,workspace,tmp,inputs,etc,run/provenance/test-secrets}
install -m 0444 /dev/null /tmp/measured-route-source/etc/resolv.conf
LD_LIBRARY_PATH="$2/lib" "$2/mksquashfs" /tmp/measured-route-source "$3/image.squashfs" \
  -noappend -no-recovery -processors 1 -mkfs-time 0 -all-time 0 >/dev/null
chmod 0444 "$3/image.squashfs"
