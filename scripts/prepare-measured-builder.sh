#!/usr/bin/env bash
# Task-private Ubuntu Noble amd64 builder; never installs packages globally.
# Default requires root-protected ancestry. --verify-downloads is explicitly
# unprivileged research/test output and MUST NOT authorize privileged execution.
# The host ELF loader/glibc remain prerequisites: this is NOT a hermetic toolchain.
set -euo pipefail
exec python3 - "$@" <<'PY'
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile

BASE = "https://archive.ubuntu.com/ubuntu/"
# Paths and package SHA256 values from Ubuntu Noble's distribution package
# indexes. Only named regular ELF files are copied; no package scripts run.
PACKAGES = [
 ("pool/main/s/squashfs-tools/squashfs-tools_4.6.1-1build1_amd64.deb",
  "87fae263846bab255d4a51ad9fc623685497ad830db60758dde39589c9fdadcb",
  [("./usr/bin/mksquashfs", "mksquashfs", "47d5c1af3da11864e64c9dc6bb4e568719dcc315e6a744e79381ce3374fb7393")]),
 ("pool/main/l/lzo2/liblzo2-2_2.10-2build4_amd64.deb",
  "e0d13be155013138b8db4cfe68212b866080af661c78302c2eab0d2f9d0d454e",
  [("./lib/x86_64-linux-gnu/liblzo2.so.2.0.0", "lib/liblzo2.so.2", "67a7624b45b4af0dd0d61122cfe16cf26353533a6b9d443179f6ec72093e0d48")]),
 ("pool/main/l/lz4/liblz4-1_1.9.4-1build1.1_amd64.deb",
  "319331270d5cc52d5ebffe51c941d7b01b432bc402c2924b557209a64d4ecbad",
  [("./usr/lib/x86_64-linux-gnu/liblz4.so.1.9.4", "lib/liblz4.so.1", "40bffd0a098387368b16b992abd5f7cf43c0fa2f05cabe5a6d483719554adfda")]),
 ("pool/main/x/xz-utils/liblzma5_5.6.1+really5.4.5-1ubuntu0.3_amd64.deb",
  "d2eabd41ca77d2c2dd9d5d4ef478cccb64ffde6279c47cf4699a857d46785a52",
  [("./usr/lib/x86_64-linux-gnu/liblzma.so.5.4.5", "lib/liblzma.so.5", "696e868dd0700a19a6d65fc01608ec2d70d3cb91f65710e89180cd2e688f30cb")]),
 ("pool/main/libz/libzstd/libzstd1_1.5.5+dfsg2-2build1.1_amd64.deb",
  "dfcf25061e07aad7efd3f4f880ba5ad4d4d09ebe7fc8cc77ab6b8a161d6d4727",
  [("./usr/lib/x86_64-linux-gnu/libzstd.so.1.5.5", "lib/libzstd.so.1", "0a2128bc10841fb29e76d08d945864dfb0b6a66da5df6df5d8299197439e54bb")]),
 ("pool/main/z/zlib/zlib1g_1.3.dfsg-3.1ubuntu2.2_amd64.deb",
  "84b9cf5752b29c9f92c27cd4c4ba9bbcc70b5ccf9b1b515421a28ae23212e273",
  [("./usr/lib/x86_64-linux-gnu/libz.so.1.3", "lib/libz.so.1", "86200da370f20476a2507e9097a789b5ef97269b4ca8d5e164ad82dab9d99892")]),
]


def ancestry(destination, protected):
    if not destination.is_absolute() or destination != destination.resolve():
        raise ValueError("destination must be absolute and canonical")
    for parent in [destination.parent, *destination.parent.parents]:
        s = parent.lstat()
        if not stat.S_ISDIR(s.st_mode):
            raise ValueError("non-directory ancestry")
        if protected and (s.st_uid != 0 or s.st_mode & 0o022):
            raise ValueError("privileged builder ancestry must be root-owned and nonwritable")
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination already exists")


def unpack(package, wanted, destination):
    result = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(package)],
                            check=True, stdout=subprocess.PIPE, timeout=20)
    if len(result.stdout) > 32 << 20:
        raise ValueError("package expansion bound")
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        members = archive.getmembers()
        for source, target, expected in wanted:
            found = [m for m in members if m.name == source]
            if len(found) != 1 or not found[0].isfile() or not 0 < found[0].size <= 4 << 20:
                raise ValueError("invalid package file")
            data = archive.extractfile(found[0]).read()
            if data[:4] != b"\x7fELF" or hashlib.sha256(data).hexdigest() != expected:
                raise ValueError("ELF identity mismatch")
            path = destination / target
            with path.open("xb") as output:
                output.write(data)
            path.chmod(0o555 if target == "mksquashfs" else 0o444)


def main():
    args = sys.argv[1:]
    protected = True
    if args and args[0] == "--verify-downloads":
        protected = False
        args = args[1:]
    if len(args) != 1 or (protected and os.geteuid() != 0):
        raise ValueError("usage: sudo prepare-measured-builder.sh NEW_ABSOLUTE_DESTINATION")
    if os.uname().machine != "x86_64":
        raise ValueError("builder requires x86_64")
    destination = Path(args[0])
    ancestry(destination, protected)
    os.umask(0o077)
    # Atomic creation: never adopt or overwrite an existing staging tree.
    destination.mkdir(mode=0o700)
    (destination / "lib").mkdir(mode=0o700)
    (destination / "packages").mkdir(mode=0o700)
    package_records, libraries = [], []
    for relative, expected, wanted in PACKAGES:
        package = destination / "packages" / Path(relative).name
        subprocess.run(["curl", "--fail", "--silent", "--show-error", "--proto", "=https",
                        "--max-time", "45", "--max-filesize", "16777216",
                        "--output", str(package), BASE + relative], check=True, timeout=50)
        data = package.read_bytes()
        if not 0 < len(data) <= 16 << 20 or hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("package identity mismatch")
        unpack(package, wanted, destination)
        package.chmod(0o444)
        package_records.append({"url": BASE + relative, "sha256": expected, "bytes": len(data)})
        libraries.extend({"name": target[4:], "sha256": digest} for _, target, digest in wanted if target.startswith("lib/"))
    manifest = {"version": 1, "protected": protected, "hermeticToolchain": False,
                "builder": str(destination / "mksquashfs"),
                "builderSha256": PACKAGES[0][2][0][2],
                "libraryDirectory": str(destination / "lib"), "libraries": libraries,
                "packages": package_records,
                "hostPrerequisite": "Compatible x86_64 ELF loader and glibc/libm; validate actual builder execution and repeated image hashes. Scope LD_LIBRARY_PATH only to the builder and clear LD_PRELOAD/LD_AUDIT."}
    with (destination / "manifest.json").open("x") as output:
        json.dump(manifest, output, indent=2)
    (destination / "manifest.json").chmod(0o444)
    for folder in (destination / "lib", destination / "packages", destination):
        folder.chmod(0o555)
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
PY
