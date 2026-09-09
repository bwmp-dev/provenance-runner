#!/usr/bin/env python3
"""Prepare one operator-trusted Paper runtime from local checksum-pinned inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit


class Invalid(ValueError):
    pass


def require(condition):
    if not condition:
        raise Invalid('preparation input or output rejected')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def checked_copy(path, destination, pin):
    require(type(pin['sizeBytes']) is int and 0 < pin['sizeBytes'] <= 512 << 20)
    require(isinstance(pin['sha256'], str) and re.fullmatch('[0-9a-f]{64}', pin['sha256']))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    with os.fdopen(fd, 'rb') as source, destination.open('xb') as target:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode))
        require(os.fstat(source.fileno()).st_size == pin['sizeBytes'])
        total = 0
        while block := source.read(1024 * 1024):
            total += len(block)
            require(total <= pin['sizeBytes'])
            target.write(block)
            digest.update(block)
    require(total == pin['sizeBytes'] and digest.hexdigest() == pin['sha256'])


def name_of(value):
    value = value.rstrip('/')
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and '..' not in path.parts and str(path) == value and len(value) <= 4096)
    return path


def extract_java(source, root, maximum):
    require(type(maximum) is int and 0 < maximum <= 1 << 30)
    entries = {}
    total = 0
    with tarfile.open(source, 'r:*') as archive:
        for item in archive:
            name = name_of(item.name)
            require(name not in entries and len(entries) < 100000)
            require(item.isdir() or item.isfile() or item.issym())
            require(not item.mode & 0o6000 and item.size >= 0)
            total += item.size
            require(total <= maximum)
            entries[name] = item
        for name, item in entries.items():
            for parent in name.parents:
                require(parent not in entries or entries[parent].isdir())
            if item.issym():
                require(item.linkname and not PurePosixPath(item.linkname).is_absolute() and len(item.linkname) <= 4096)
        # Root is a fresh private temporary directory; never follow archive links
        # while writing. Links are created only after every ordinary file.
        for name, item in entries.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if item.isdir():
                path.mkdir(exist_ok=True)
            elif item.isfile():
                with archive.extractfile(item) as src, path.open('xb') as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                path.chmod(0o755 if item.mode & 0o111 else 0o644)
        for name, item in entries.items():
            if item.issym():
                (root / name).symlink_to(item.linkname)
        for name, item in entries.items():
            if item.issym():
                try:
                    resolved = (root / name).resolve(strict=True)
                except (OSError, RuntimeError) as error:
                    raise Invalid('invalid archive link') from error
                require(resolved.is_relative_to(root.resolve()))
    return total


def prepare(args):
    with Path(args.catalog).open('rb') as source:
        raw = source.read(65537)
    require(len(raw) <= 65536)
    catalog = json.loads(raw, object_pairs_hook=unique)
    uri = urlsplit(args.runtime_uri)
    require(uri.scheme == 'https' and uri.hostname and not uri.username and not uri.password and not uri.fragment)
    require(len(args.runtime_uri) <= 8192 and not any(ord(c) < 33 for c in args.runtime_uri))
    output = Path(args.output_dir)
    # Exclusive directory creation gives both outputs one ownership boundary;
    # existing outputs are never overwritten, including symlinks.
    output.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix='paper-catalog-') as temporary:
            work = Path(temporary)
            checked_copy(args.java_archive, work / 'java.tar', catalog['java']['artifact'])
            checked_copy(args.paper, work / 'paper.jar', catalog['paper']['artifact'])
            java_root = work / 'java'
            java_root.mkdir()
            extract_java(work / 'java.tar', java_root, catalog['java']['maximumExpandedBytes'])
            archive_root = name_of(catalog['java']['archiveRoot'])
            java = java_root / archive_root / 'bin/java'
            require(java.resolve().is_relative_to((java_root / archive_root).resolve()) and java.is_file() and os.access(java, os.X_OK))
            selection = work / 'catalog.json'
            selection.write_bytes(raw)
            prepared = work / 'paper-runtime.tar.gz'
            # Only trusted Paperclip and verified Java are executed. Capture no
            # provider/subprocess output: it can contain private catalog URLs.
            with open(os.devnull, 'wb') as quiet:
                subprocess.run([str(Path(args.runtime_tool).resolve()), '-catalog', str(selection), '-paper', str(work / 'paper.jar'), '-java', str(java), '-output', str(prepared)], check=True, stdout=quiet, stderr=quiet, timeout=600)
            require(prepared.is_file() and not prepared.is_symlink() and 0 < prepared.stat().st_size <= 512 << 20)
            with prepared.open('rb') as file:
                digest = hashlib.file_digest(file, 'sha256').hexdigest()
            # Prepared archives are independently bounded again at runner use.
            catalog['preparedRuntime'] = {'artifact': {'uri': args.runtime_uri, 'sha256': digest, 'sizeBytes': prepared.stat().st_size, 'filename': 'paper-runtime.tar.gz'}, 'maximumExpandedBytes': args.maximum_prepared_bytes}
            require(0 < args.maximum_prepared_bytes <= 1 << 30)
            shutil.copyfile(prepared, output / 'paper-runtime.tar.gz')
            (output / 'paper-runtime.tar.gz').chmod(0o600)
            fd = os.open(output / 'catalog.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as file:
                json.dump(catalog, file, indent=2)
                file.write('\n')
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('catalog', 'java-archive', 'paper', 'runtime-tool', 'runtime-uri', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--maximum-prepared-bytes', type=int, required=True)
    try:
        prepare(parser.parse_args())
    except (Invalid, OSError, ValueError, KeyError, TypeError, RuntimeError, tarfile.TarError, subprocess.SubprocessError):
        print('Paper catalog preparation failed; details withheld', file=sys.stderr)
        return 1
    print('Paper catalog and verified runtime prepared')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
