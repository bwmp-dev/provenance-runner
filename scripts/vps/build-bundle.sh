#!/usr/bin/env bash
# Build on a trusted Linux amd64 machine with Go, Docker, curl and Python 3.
set -euo pipefail
[[ $# == 1 && $1 == /* && ! -e $1 ]] || { echo 'usage: build-bundle.sh /absolute/new-bundle-directory' >&2; exit 2; }
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
[[ -z $(git status --porcelain --untracked-files=no) ]] || { echo 'Commit tracked changes before creating a release bundle.' >&2; exit 1; }
commit=$(git rev-parse HEAD)
mkdir -m 700 "$1"
out=$1
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
go build -trimpath -ldflags "-X github.com/bwmp-dev/provenance-runner/internal/buildinfo.Version=git-${commit:0:12} -X github.com/bwmp-dev/provenance-runner/internal/buildinfo.Commit=$commit" -o "$out/runner" ./cmd/provenance-runner
curl --fail --location --proto '=https' --proto-redir '=https' --max-time 300 --output "$out/gvisor.tar.bz2" https://storage.googleapis.com/gvisor/releases/nightly/2026-08-30/x86_64/gvisor.tar.bz2
printf '%s  %s\n' e8eb6473e5a27316df551cbb40e5626e51df1b602bde2621f77d851c2c53b0387e282c7ebc0ee80ceb07a26e152e67b4af3e17550009e2c486e2f19666570449 "$out/gvisor.tar.bz2" | sha512sum -c -
python3 - "$out" <<'PY'
import pathlib, tarfile, hashlib, sys
p=pathlib.Path(sys.argv[1])
with tarfile.open(p/'gvisor.tar.bz2') as t:
    members=[m for m in t if m.name=='runsc']
    assert len(members)==1 and members[0].isfile() and 0 < members[0].size < 512*1024*1024
    data=t.extractfile(members[0]).read()
    assert hashlib.sha256(data).hexdigest()=='456ea862b62b48bb7ff27ae38c262b52315bf3d68ea0733164e4817cadc518a1'
    (p/'runsc').write_bytes(data)
(p/'gvisor.tar.bz2').unlink()
PY
image=ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517
docker pull --platform linux/amd64 "$image"
container=$(docker create --platform linux/amd64 "$image")
trap 'docker rm "$container" >/dev/null 2>&1 || true' EXIT
docker export --output "$out/rootfs.tar" "$container"
docker rm "$container" >/dev/null
trap - EXIT
cp scripts/vps/install.sh scripts/vps/install.py scripts/vps/updater.py scripts/vps/sign-release.py scripts/vps/sign-catalog.py "$out/"
cp scripts/prepare-gvisor-rootfs.sh "$out/"
cp scripts/vps/settings.example.json "$out/settings.example.json"
printf '%s\n' "$commit" > "$out/SOURCE_COMMIT"
chmod 755 "$out/runner" "$out/runsc" "$out/install.sh" "$out/prepare-gvisor-rootfs.sh"
(cd "$out" && sha256sum runner runsc rootfs.tar install.sh install.py prepare-gvisor-rootfs.sh settings.example.json SOURCE_COMMIT updater.py sign-release.py sign-catalog.py > SHA256SUMS)
printf 'Bundle ready: %s\nCopy it securely to /root on the VPS; see docs/vps-install.md.\n' "$out"
