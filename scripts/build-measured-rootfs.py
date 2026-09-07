#!/usr/bin/env python3
"""Build only: pinned source -> reproducible exclusive SquashFS generation.

Does not install, mount, replace, activate, or infer a production image pin.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

MAX_SOURCE = 512 << 20
MAX_EXPANDED = 4 << 30
MAX_ENTRIES = 100000
OPTIONS = ["-noappend", "-no-recovery", "-processors", "1", "-mkfs-time", "0", "-all-time", "0"]
TARGETS = {"": 0o711, "proc": 0o700, "dev": 0o700, "dev/pts": 0o700,
           "workspace": 0o700, "tmp": 0o1700, "inputs": 0o700, "runtime": 0o700}


class Invalid(Exception):
    pass


def bounded_file(path, limit):
    path = Path(path)
    if not path.is_absolute() or str(path.resolve()) != str(path):
        raise Invalid("input path must be canonical")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    file = os.fdopen(fd, "rb")
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > limit:
        file.close()
        raise Invalid("input size/type invalid")
    return file


def digest(file):
    file.seek(0)
    before = os.fstat(file.fileno())
    result = hashlib.file_digest(file, "sha256").hexdigest()
    after = os.fstat(file.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise Invalid("input changed")
    file.seek(0)
    return result


def canonical_name(name):
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if name in ("", "."):
        return ""
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or str(p) != name or len(p.parts) > 64 or len(name) > 4096:
        raise Invalid("unsafe archive path")
    return name


def extract(source, root, uid, gid):
    entries = {}
    total = 0
    with tarfile.open(fileobj=source, mode="r:*") as archive:
        for member in archive:
            name = canonical_name(member.name)
            if name in entries or len(entries) >= MAX_ENTRIES:
                raise Invalid("duplicate/excess archive entries")
            if not (member.isdir() or member.isfile() or member.issym()) or member.mode & 0o6000:
                raise Invalid("unsupported archive object")
            if not (0 <= member.uid <= 4294967294 and 0 <= member.gid <= 4294967294):
                raise Invalid("invalid archive ownership")
            if not name and not member.isdir():
                raise Invalid("archive root must be directory")
            entries[name] = member
            total += member.size
            if member.size < 0 or total > MAX_EXPANDED:
                raise Invalid("archive expanded bound")
        # Validate every parent before creating any archive object. Symlinks
        # are guest paths, never extraction traversal or host path references.
        for name, member in entries.items():
            for parent in PurePosixPath(name).parents:
                value = entries.get(str(parent))
                if value is not None and not value.isdir():
                    raise Invalid("archive parent is not directory")
            if member.issym():
                target = PurePosixPath(member.linkname)
                base = [] if target.is_absolute() else list(PurePosixPath(name).parent.parts)
                for part in target.parts:
                    if part in ("/", "."):
                        continue
                    if part == "..":
                        if not base:
                            raise Invalid("guest symlink escapes root")
                        base.pop()
                    else:
                        base.append(part)
                if not member.linkname or "\0" in member.linkname:
                    raise Invalid("invalid symlink")
        # Resolve guest symlink chains lexically against archive members, not
        # the host filesystem. A later '..' must not escape after an earlier
        # link resolves to a shallower guest directory.
        for name, member in entries.items():
            if not member.issym():
                continue
            pending = list(PurePosixPath(name).parts)
            resolved = []
            followed = 0
            while pending:
                part = pending.pop(0)
                if part in ("", ".", "/"):
                    continue
                if part == "..":
                    if not resolved:
                        raise Invalid("guest symlink chain escapes root")
                    resolved.pop()
                    continue
                item = entries.get("/".join([*resolved, part]))
                if item is not None and item.issym():
                    followed += 1
                    if followed > 64:
                        raise Invalid("cyclic/excess symlink chain")
                    target = PurePosixPath(item.linkname)
                    if target.is_absolute():
                        resolved = []
                    pending = list(target.parts) + pending
                else:
                    resolved.append(part)
        for name, member in sorted(entries.items(), key=lambda item: (item[0].count("/"), item[0])):
            target = root / name
            if not name:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(exist_ok=True)
                os.chmod(target, member.mode & 0o777)
            elif member.issym():
                target.symlink_to(member.linkname)
            else:
                with archive.extractfile(member) as src, open(target, "xb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 16)
                os.chmod(target, member.mode & 0o777)
        # Preserve ownership without following guest symlinks. Inability to do
        # so is an error, never an implicit all-root conversion.
        for name, member in entries.items():
            if name:
                os.chown(root / name, member.uid, member.gid, follow_symlinks=False)
    # Preserve regular image metadata, except the established runner-owned
    # mount targets. Privileged installation is a separate operation.
    for name, mode in TARGETS.items():
        target = root / name
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            raise Invalid("unsafe mount target")
        target.mkdir(parents=True, exist_ok=True)
        allowed = {"pts"} if name == "dev" else set()
        if name and any(child.name not in allowed for child in target.iterdir()):
            raise Invalid("nonempty mount target")
        os.chown(target, uid, gid)
        os.chmod(target, mode)
    event = root / "tmp/provenance-probe-events.ndjson"
    with open(event, "xb"):
        pass
    os.chown(event, uid, gid)
    os.chmod(event, 0o600)


def tree_digest(root):
    result = hashlib.sha256()
    for path in sorted([root, *root.rglob("*")]):
        s = path.lstat()
        result.update(json.dumps([str(path.relative_to(root)), s.st_mode, s.st_uid, s.st_gid], separators=(",", ":")).encode())
        if path.is_symlink():
            result.update(os.readlink(path).encode())
        elif path.is_file():
            with open(path, "rb") as file:
                result.update(hashlib.file_digest(file, "sha256").digest())
        elif not path.is_dir():
            raise Invalid("staging special file")
    return result.digest()


def build(args):
    for value in (args.source_sha256, args.builder_sha256):
        if not re.fullmatch(r"[a-f0-9]{64}", value):
            raise Invalid("pin must be SHA256")
    if args.uid < 0 or args.gid < 0 or args.uid > 4294967294 or args.gid > 4294967294:
        raise Invalid("invalid runner ownership")
    output = Path(args.output)
    if not output.is_absolute() or output.is_symlink() or str(output.resolve()) != str(output):
        raise Invalid("output must be canonical directory")
    output.mkdir(mode=0o700, exist_ok=True)
    with bounded_file(args.source, MAX_SOURCE) as source, bounded_file(args.builder, MAX_SOURCE) as builder:
        if digest(source) != args.source_sha256 or digest(builder) != args.builder_sha256:
            raise Invalid("source/builder identity mismatch")
        images = []
        with tempfile.TemporaryDirectory(prefix=".measured-rootfs-", dir=output) as staging:
            staging = Path(staging)
            for index in range(2):
                root = staging / f"tree-{index}"
                root.mkdir(mode=0o700)
                source.seek(0)
                extract(source, root, args.uid, args.gid)
                before = tree_digest(root)
                image = staging / f"image-{index}.squashfs"
                # Linux FD execution binds the pinned builder object, not a
                # second resolution of its supplied pathname.
                subprocess.run([f"/proc/self/fd/{builder.fileno()}", str(root), str(image), *OPTIONS],
                               pass_fds=(builder.fileno(),), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=120, check=True)
                if tree_digest(root) != before or digest(source) != args.source_sha256 or digest(builder) != args.builder_sha256:
                    raise Invalid("source/builder/staging changed")
                with bounded_file(image, MAX_EXPANDED) as file:
                    images.append((image, digest(file)))
            if images[0][1] != images[1][1]:
                raise Invalid("independent image builds differ")
            identity = images[0][1]
            destination = output / f"sha256-{identity}.squashfs"
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            try:
                with os.fdopen(fd, "wb") as dst, open(images[0][0], "rb") as src:
                    shutil.copyfileobj(src, dst, 1 << 16)
                    dst.flush()
                    os.fsync(dst.fileno())
            except BaseException:
                destination.unlink()
                raise
            directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return {"format": "squashfs-image-sha256/v1", "sha256": identity,
                    "sizeBytes": destination.stat().st_size, "sourceSha256": args.source_sha256,
                    "builderSha256": args.builder_sha256, "builderOptions": OPTIONS,
                    "runnerUid": args.uid, "runnerGid": args.gid, "reproducibleBuilds": 2}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("source", "source-sha256", "builder", "builder-sha256", "output"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    try:
        print(json.dumps(build(parser.parse_args()), sort_keys=True, separators=(",", ":")))
    except (Invalid, OSError, tarfile.TarError, subprocess.SubprocessError):
        parser.exit(1, "measured rootfs build refused\n")
