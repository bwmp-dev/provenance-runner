#!/usr/bin/env bash
# Bounded CI/disposable-container driver; never contacts the production runner.
set -euo pipefail
[[ $# == 4 ]]
runsc=$1 builder=$2 scratch=$3 evidence=$4
[[ "$runsc" == /* && "$builder" == /* && "$scratch" == /* && "$evidence" == /* ]]
[[ ! -e "$scratch" && ! -e "$evidence" ]]
mkdir -m 0700 "$scratch" "$evidence"
source_image='ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517'
name="provenance-generation-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
source_container='' test_container=''
cleanup() {
  code=$?
  if [[ -n "$source_container" ]]; then docker rm "$source_container" >/dev/null || code=1; fi
  if [[ -n "$test_container" ]]; then
    docker logs "$test_container" > "$evidence/fixture.log" 2>&1 || code=1
    # Successful driver cleanup is a precondition for removal. Keep failed
    # containers/resources inspectable rather than delete evidence/backing.
    if [[ "$code" == 0 ]]; then docker rm "$test_container" >/dev/null || code=1; fi
  fi
  exit "$code"
}
trap cleanup EXIT
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
test_container=$(docker create --name "$name-test" --privileged --network none \
  --mount "type=bind,src=$PWD,dst=/repo,readonly" \
  --mount "type=bind,src=$scratch,dst=/inputs,readonly" \
  --mount "type=bind,src=$runsc,dst=/runsc-input,readonly" \
  --mount "type=bind,src=$builder,dst=/builder-input,readonly" \
  "$name-tools" bash /repo/scripts/test-runtime-generation-fixture.sh \
  /inputs/source.tar /runsc-input /builder-input /inputs/identity.test /inputs/gvisor.test /inputs/runner)
docker start --attach "$test_container"
[[ $(docker inspect --format '{{.State.ExitCode}}' "$test_container") == 0 ]]
docker logs "$test_container" > "$evidence/fixture.log" 2>&1
python3 - "$evidence/fixture.log" <<'PY'
import pathlib,sys
t=pathlib.Path(sys.argv[1]).read_text()
assert '--- SKIP:' not in t
for name in ['wrong-image-inode','writable-image','executable-symlink','not-squashfs']:
    assert '--- PASS: TestRuntimeMountFixture/'+name in t
assert '--- PASS: TestMeasuredPreflightWithProtectedImageFiles' in t
assert '"allOwnedLoopsDetached": true' in t
PY
( cd "$evidence" && sha256sum fixture.log source-image.txt tooling-image.txt > manifest.sha256 )
