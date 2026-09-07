#!/usr/bin/env bash
# Bounded CI/disposable-container driver; never contacts the production runner.
set -euo pipefail
[[ $# == 4 || $# == 5 || $# == 8 ]]
runsc=$1 builder=$2 scratch=$3 evidence=$4
phase=${5:-all}
[[ "$phase" == all || "$phase" == prepare || "$phase" == execute ]]
[[ "$runsc" == /* && "$builder" == /* && "$scratch" == /* && "$evidence" == /* ]]
if [[ "$phase" != execute ]]; then
  [[ ! -e "$scratch" && ! -e "$evidence" ]]
  mkdir -m 0700 "$scratch" "$evidence"
fi
source_image='ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517'
name="provenance-generation-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
source_container='' test_container=''
cleanup() {
  code=$?
  if [[ -n "$source_container" ]]; then docker rm "$source_container" >/dev/null || code=1; fi
  if [[ -n "$test_container" ]]; then
    # Never leave a running profiled process behind, including interruption.
    if [[ $(docker inspect --format '{{.State.Running}}' "$test_container") == true ]]; then
      docker stop --time 10 "$test_container" >/dev/null || code=1
    fi
    [[ $(docker inspect --format '{{.State.Running}}' "$test_container") == false ]] || code=1
    docker logs "$test_container" > "$evidence/fixture.log" 2>&1 || code=1
    # Successful driver cleanup is a precondition for removal. Keep failed
    # containers/resources inspectable rather than delete evidence/backing.
    if [[ "$code" == 0 ]]; then docker rm "$test_container" >/dev/null || code=1; fi
  fi
  exit "$code"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
if [[ "$phase" != execute ]]; then
docker pull "$source_image"
source_container=$(docker create --name "$name-source" "$source_image")
docker export --output "$scratch/source.tar" "$source_container"
docker image inspect "$source_image" --format '{{.Id}}' > "$evidence/source-image.txt"
CGO_ENABLED=0 go test -c -ldflags '-X github.com/bwmp-dev/provenance-runner/internal/buildinfo.Version=0.1.0-alpha' \
  -o "$scratch/identity.test" ./internal/runtimeidentity
CGO_ENABLED=0 go test -c -ldflags '-X github.com/bwmp-dev/provenance-runner/internal/buildinfo.Version=0.1.0-alpha' \
  -o "$scratch/gvisor.test" ./internal/provider/gvisor
CGO_ENABLED=0 go build -ldflags '-X github.com/bwmp-dev/provenance-runner/internal/buildinfo.Version=0.1.0-alpha' \
  -o "$scratch/runner" ./cmd/provenance-runner
docker build --tag "$name-tools" --file scripts/runtime-generation-fixture.Dockerfile .
docker image inspect "$name-tools" --format '{{.Id}}' > "$evidence/tooling-image.txt"
fi
[[ "$phase" != prepare ]] || exit 0
tool_image=$(< "$evidence/tooling-image.txt")
[[ "$tool_image" =~ ^sha256:[a-f0-9]{64}$ ]]
profile_mount=()
if [[ "$phase" == execute ]]; then
  [[ $# == 8 && $(id -u) == 0 ]]
  attachment=$6 fixture_uid=$7 fixture_gid=$8
  [[ "$attachment" =~ ^/var/lib/provenance-measurement-ci\.[A-Za-z0-9]{8}/gvisor-smoke.test$ ]]
  [[ "$fixture_uid" =~ ^6[0-3][0-9]{3}$ && "$fixture_gid" =~ ^[0-9]+$ ]]
  python3 scripts/runtime-generation-profile-binding.py record "$attachment" "$fixture_uid" "$fixture_gid" "$evidence/profile-binding.json"
  profile_mount=(--mount "type=bind,src=$attachment,dst=$attachment,readonly"
    --mount "type=bind,src=$evidence/profile-binding.json,dst=/profile-binding.json,readonly"
    --env "PROVENANCE_MEASUREMENT_FIXTURE_UID=$fixture_uid"
    --env "PROVENANCE_MEASUREMENT_FIXTURE_GID=$fixture_gid"
    --env "PROVENANCE_MEASUREMENT_EXPECTED_PROFILE=pvm-measured-$(basename "$(dirname "$attachment")" | cut -d. -f2)"
    --env "PROVENANCE_MEASUREMENT_FIXTURE_LAUNCHER=$attachment")
fi
test_container=$(docker create --name "$name-test" --privileged --network none \
  "${profile_mount[@]}" \
  --mount "type=bind,src=$PWD,dst=/repo,readonly" \
  --mount "type=bind,src=$scratch,dst=/inputs,readonly" \
  --mount "type=bind,src=$runsc,dst=/runsc-input,readonly" \
  --mount "type=bind,src=$builder,dst=/builder-input,readonly" \
  "$tool_image" bash /repo/scripts/test-runtime-generation-fixture.sh \
  /inputs/source.tar /runsc-input /builder-input /inputs/identity.test /inputs/gvisor.test /inputs/runner)
docker start --attach "$test_container"
[[ $(docker inspect --format '{{.State.ExitCode}}' "$test_container") == 0 ]]
if [[ "$phase" == execute ]]; then
  python3 scripts/runtime-generation-profile-binding.py verify "$attachment" "$fixture_uid" "$fixture_gid" "$evidence/profile-binding.json"
fi
docker logs "$test_container" > "$evidence/fixture.log" 2>&1
python3 - "$evidence/fixture.log" <<'PY'
import json,pathlib,sys
t=pathlib.Path(sys.argv[1]).read_text()
assert '--- SKIP:' not in t
for name in ['wrong-image-inode','writable-image','executable-symlink','not-squashfs']:
    assert '--- PASS: TestRuntimeMountFixture/'+name in t
assert '--- PASS: TestMeasuredPreflightWithProtectedImageFiles' in t
assert '"allOwnedLoopsDetached": true' in t
records=[json.loads(line) for line in t.splitlines() if line.startswith('{')]
matrix=next(row['failureMatrix'] for row in records if 'failureMatrix' in row)
assert len(matrix)==45 and len({row['stage'] for row in matrix})==45
assert all(row['injectionReached'] and not row['postCleanup']['associatedLoops'] and not row['postCleanup']['mounted'] for row in matrix)
cli=next(row for row in records if 'cliTests' in row)
assert 'full-cli-install-verify-select-rollback-idempotence' in cli['cliTests']
assert 'full-cli-journalled-recovery' in cli['cliTests']
summary=next(row for row in records if 'cleanupObservations' in row)
assert summary['cleanupObservations'] and all(not row['associatedLoops'] and not row['mounted'] for row in summary['cleanupObservations'])
PY
( cd "$evidence" && shopt -s nullglob && sha256sum -- *.log *.txt *.json > manifest.sha256 )
