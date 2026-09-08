#!/usr/bin/env bash
# Only a fresh private Docker guest; no host service or security-policy writes.
set -euo pipefail
[[ $# == 1 && $1 =~ ^sha256:[a-f0-9]{64}$ ]]
image=$1
command -v docker >/dev/null
scripts=$(cd -- "$(dirname -- "$0")" && pwd)
container=
cleanup() {
  result=$?
  trap - EXIT
  if [[ -n "$container" ]]; then
    [[ $(docker inspect --format '{{index .Config.Labels "provenance.fixture"}}' "$container") == wp10a-baseline ]] || exit 1
    [[ $(docker inspect --format '{{.Image}}' "$container") == "$image" ]] || exit 1
    docker stop --timeout 20 "$container" >/dev/null || exit 1
    [[ $(docker inspect --format '{{.State.Running}}' "$container") == false ]] || exit 1
    docker rm "$container" >/dev/null || exit 1
    if docker inspect "$container" >/dev/null 2>&1; then exit 1; fi
    printf '{"container":"%s","exactContainerCleanup":true,"testExit":%s}\n' "$container" "$result"
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
container=$(docker run -d --label provenance.fixture=wp10a-baseline --network none \
  --privileged --cgroupns private --tmpfs /run --tmpfs /run/lock "$image")
[[ $container =~ ^[a-f0-9]{64}$ ]]
[[ $(docker inspect --format '{{.HostConfig.PidMode}}/{{.HostConfig.CgroupnsMode}}/{{.HostConfig.NetworkMode}}/{{len .Mounts}}' "$container") == /private/none/0 ]]
for attempt in {1..60}; do
  if docker exec "$container" systemctl is-system-running --quiet 2>/dev/null; then break; fi
  sleep 0.5
done
docker exec "$container" systemctl is-system-running --quiet
docker cp "$scripts/runtime-baseline.py" "$container:/opt/runtime-baseline.py"
docker cp "$scripts/test-runtime-baseline-fixture.py" "$container:/opt/test-runtime-baseline-fixture.py"
docker exec "$container" python3 -c 'from pathlib import Path; p=Path("/run/provenance-baseline-disposable"); f=p.open("x"); f.write("wp10a-disposable-only\n"); f.close()'
printf '{"fixtureImage":"%s","container":"%s","realSystemManager":true}\n' "$image" "$container"
timeout 180s docker exec "$container" python3 /opt/test-runtime-baseline-fixture.py
