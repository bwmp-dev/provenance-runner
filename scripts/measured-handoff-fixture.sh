#!/usr/bin/env bash
# Only in a fresh, network-none disposable container, with read-only test inputs.
set -euo pipefail
[[ $(id -u) == 0 && -f /.dockerenv && ! -e /tmp/provenance-runtime-fixture ]]
[[ $# == 5 ]]
cp "$1" /tmp/runtimeidentity.test
cp "$2" /tmp/gvisor-preflight.test
cp "$3" /tmp/measured-runner
cp "$4" /tmp/runsc
cp "$5/mksquashfs" /tmp/mksquashfs
chmod 0555 /tmp/runtimeidentity.test /tmp/gvisor-preflight.test /tmp/measured-runner /tmp/runsc /tmp/mksquashfs
LD_LIBRARY_PATH="$5/lib" bash /repo/scripts/runtime-measurement-fixture.sh
