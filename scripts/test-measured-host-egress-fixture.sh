#!/usr/bin/env bash
# Never joins the host network namespace or mounts host data into the guest.
set -euo pipefail
[[ $# == 1 && $1 =~ ^sha256:[a-f0-9]{64}$ ]]
image=$1
scripts=$(cd -- "$(dirname -- "$0")" && pwd)
container=
cleanup() {
  result=$?
  trap - EXIT
  if [[ -n "$container" ]]; then
    [[ $(docker inspect --format '{{index .Config.Labels "provenance.fixture"}}' "$container") == measured-host-egress ]] || exit 1
    [[ $(docker inspect --format '{{.Image}}' "$container") == "$image" ]] || exit 1
    docker stop --timeout 10 "$container" >/dev/null || exit 1
    [[ $(docker inspect --format '{{.State.Running}}' "$container") == false ]] || exit 1
    if [[ $result == 0 ]]; then
      docker rm "$container" >/dev/null || exit 1
      printf '{"exactEgressContainerRemoved":true}\n'
    else
      printf '{"stoppedEgressContainerRetained":"%s"}\n' "$container"
    fi
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
container=$(docker create --label provenance.fixture=measured-host-egress --network none \
  --privileged --cgroupns private --memory 256m --memory-swap 256m --cpus 1 --pids-limit 128 \
  --entrypoint python3 "$image" -I /test-measured-host-egress-fixture.py)
[[ "$container" =~ ^[a-f0-9]{64}$ ]]
[[ $(docker inspect --format '{{.HostConfig.PidMode}}/{{.HostConfig.NetworkMode}}/{{len .Mounts}}' "$container") == /none/0 ]]
for file in measured-host-egress.py test-measured-host-egress-fixture.py; do
  docker cp "$scripts/$file" "$container:/$file"
done
timeout 120s docker start --attach "$container"
[[ $(docker inspect --format '{{.State.ExitCode}}' "$container") == 0 ]]
