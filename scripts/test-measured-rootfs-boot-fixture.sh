#!/usr/bin/env bash
# Fresh synthetic systemd guest only. No host mounts or service changes.
set -euo pipefail
[[ $# == 1 && $1 =~ ^sha256:[a-f0-9]{64}$ ]]
image=$1
scripts=$(cd -- "$(dirname -- "$0")" && pwd)
container=
cleanup() {
  result=$?
  trap - EXIT
  if [[ -n "$container" ]]; then
    [[ $(docker inspect --format '{{index .Config.Labels "provenance.fixture"}}' "$container") == measured-rootfs-boot ]] || exit 1
    [[ $(docker inspect --format '{{.Image}}' "$container") == "$image" ]] || exit 1
    docker stop --timeout 20 "$container" >/dev/null || exit 1
    [[ $(docker inspect --format '{{.State.Running}}' "$container") == false ]] || exit 1
    # Failed guests remain stopped for diagnosis, not removed with unknown loops.
    if [[ $result == 0 ]]; then
      docker rm "$container" >/dev/null || exit 1
      if docker inspect "$container" >/dev/null 2>&1; then exit 1; fi
      printf '{"exactContainerCleanup":true,"testExit":0}\n'
    else
      printf '{"stoppedGuestRetained":"%s","testExit":%s}\n' "$container" "$result"
    fi
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
container=$(docker run -d --label provenance.fixture=measured-rootfs-boot --network none \
  --privileged --cgroupns private --tmpfs /run --tmpfs /run/lock "$image")
[[ $container =~ ^[a-f0-9]{64}$ ]]
[[ $(docker inspect --format '{{.HostConfig.PidMode}}/{{.HostConfig.CgroupnsMode}}/{{.HostConfig.NetworkMode}}/{{len .Mounts}}' "$container") == /private/none/0 ]]
for attempt in {1..60}; do
  if docker exec "$container" systemctl is-system-running --quiet 2>/dev/null; then break; fi
  sleep 0.5
done
docker exec "$container" systemctl is-system-running --quiet
for file in runtime-generation.py measured-rootfs-boot.py test-measured-rootfs-boot-fixture.py; do
  docker cp "$scripts/$file" "$container:/opt/$file"
done
docker exec "$container" python3 -c 'from pathlib import Path; p=Path("/run/provenance-boot-disposable"); f=p.open("x"); f.write("measured-boot-disposable-only\n"); f.close()'
timeout 240s docker exec "$container" python3 -B /opt/test-measured-rootfs-boot-fixture.py
