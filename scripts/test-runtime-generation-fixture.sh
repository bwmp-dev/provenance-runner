#!/usr/bin/env bash
# Root only inside a new disposable container. No host service/unit changes.
set -euo pipefail
[[ $(id -u) == 0 && -f /.dockerenv ]]
[[ $# == 6 ]]
source_tar=$1 runsc_input=$2 builder_input=$3 identity_test=$4 preflight_test=$5 runner_input=$6
if [[ -n ${PROVENANCE_MEASUREMENT_FIXTURE_LAUNCHER:-} ]]; then
  python3 /repo/scripts/runtime-generation-profile-binding.py container \
    "$PROVENANCE_MEASUREMENT_FIXTURE_LAUNCHER" "$PROVENANCE_MEASUREMENT_FIXTURE_UID" \
    "$PROVENANCE_MEASUREMENT_FIXTURE_GID" /profile-binding.json
fi
mkdir -m 0711 /opt/generation-fixture
mkdir -m 0711 /opt/generation-fixture/prepared /opt/generation-fixture/output
tar --extract --file "$source_tar" --directory /opt/generation-fixture/prepared
bash /repo/scripts/prepare-gvisor-rootfs.sh prepare /opt/generation-fixture/prepared
cleanup() {
  if mountpoint -q /opt/generation-fixture/prepared; then
    bash /repo/scripts/prepare-gvisor-rootfs.sh release /opt/generation-fixture/prepared
  fi
}
trap cleanup EXIT
python3 /repo/scripts/prepare-ubuntu-measured-source.py --root /opt/generation-fixture/prepared \
  --output /opt/generation-fixture/source.tar \
  --source-oci 'ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517'
cp -a "$builder_input" /opt/generation-fixture/builder
chown -R 0:0 /opt/generation-fixture/builder
chmod -R go-w /opt/generation-fixture/builder
source_sha=$(sha256sum /opt/generation-fixture/source.tar)
source_sha=${source_sha%% *}
builder_sha=$(sha256sum /opt/generation-fixture/builder/mksquashfs)
builder_sha=${builder_sha%% *}
[[ "$builder_sha" == 47d5c1af3da11864e64c9dc6bb4e568719dcc315e6a744e79381ce3374fb7393 ]]
LD_LIBRARY_PATH=/opt/generation-fixture/builder/lib python3 /repo/scripts/build-measured-rootfs.py \
  --source /opt/generation-fixture/source.tar --source-sha256 "$source_sha" \
  --builder /opt/generation-fixture/builder/mksquashfs --builder-sha256 "$builder_sha" \
  --output /opt/generation-fixture/output --uid 1001 --gid 1001 | tee /opt/generation-fixture/image-manifest.json
cp "$identity_test" /tmp/runtimeidentity.test
cp "$preflight_test" /tmp/gvisor-preflight.test
cp "$runsc_input" /tmp/runsc
cp "$runner_input" /tmp/measured-runner
cp /opt/generation-fixture/builder/mksquashfs /tmp/mksquashfs
LD_LIBRARY_PATH=/opt/generation-fixture/builder/lib bash /repo/scripts/runtime-measurement-fixture.sh
if [[ -n ${PROVENANCE_MEASUREMENT_FIXTURE_LAUNCHER:-} ]]; then
  python3 /repo/scripts/runtime-generation-profile-binding.py container \
    "$PROVENANCE_MEASUREMENT_FIXTURE_LAUNCHER" "$PROVENANCE_MEASUREMENT_FIXTURE_UID" \
    "$PROVENANCE_MEASUREMENT_FIXTURE_GID" /profile-binding.json
fi
image=$(find /opt/generation-fixture/output -maxdepth 1 -name 'sha256-*.squashfs' -type f)
[[ -n "$image" && "$image" != *$'\n'* ]]
python3 /repo/scripts/runtime-generation-fixture.py "$image"
