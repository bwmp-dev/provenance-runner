#!/usr/bin/env python3
"""Stage bounded real-Paper fixture inputs; never execute Java or JAR content."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile

JAVA = '968c283e104059dae86ea1d670672a80170f27a39529d815843ec9c1f0fa2a03'
PAPER = '8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e'
TARGET = 'a0c881f0a9e2229143ae8cfcc5fd019de02ce96504fe66c29f90eb13aad004ba'


def identity(path):
    assert not path.is_symlink() and path.is_file()
    with path.open('rb') as file:
        return {'sha256': hashlib.file_digest(file, 'sha256').hexdigest(), 'sizeBytes': os.fstat(file.fileno()).st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java', type=Path, required=True)
    parser.add_argument('--legacy-fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert args.output.is_absolute() and args.output.resolve() == args.output and not args.output.exists()
    inputs = [('java.tar.gz', args.java, JAVA), ('paper.jar', args.legacy_fixture/'paper-1.21.8.jar', PAPER),
              ('target.jar', args.legacy_fixture/'modern-server/plugins/success.jar', TARGET)]
    for _, source, expected in inputs:
        assert source.is_absolute() and source.resolve() == source
        observed = identity(source)
        assert observed['sha256'] == expected and 0 < observed['sizeBytes'] <= 64 << 20
    prepared = args.legacy_fixture/'modern-server'
    entries = []
    expanded = 0
    for name in ('cache', 'libraries', 'versions'):
        root = prepared/name
        assert root.is_dir() and not root.is_symlink()
        for path in [root, *sorted(root.rglob('*'))]:
            mode = path.lstat().st_mode
            assert stat.S_ISDIR(mode) or stat.S_ISREG(mode)
            if stat.S_ISREG(mode):
                expanded += path.stat().st_size
            entries.append(path)
    assert 0 < expanded <= 512 << 20 and len(entries) <= 100000
    args.output.mkdir(mode=0o700)
    manifest = {'version': 1, 'gameVersion': '1.21.8', 'paperBuild': 60, 'targetPlugin': 'ProvenanceSuccess', 'inputs': {}}
    for name, source, expected in inputs:
        destination = args.output/name
        with destination.open('xb') as out, source.open('rb') as src:
            shutil.copyfileobj(src, out, 1 << 16)
        observed = identity(destination)
        assert observed['sha256'] == expected
        manifest['inputs'][name] = observed
        destination.chmod(0o444)
    archive_path = args.output/'prepared-runtime.tar.gz'
    with archive_path.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w|', format=tarfile.GNU_FORMAT) as archive:
        for path in entries:
            member = archive.gettarinfo(str(path), arcname=str(path.relative_to(prepared)))
            member.uid = member.gid = 65532
            member.uname = member.gname = ''
            member.mtime = 0
            member.mode = 0o700 if member.isdir() else 0o600
            if member.isfile():
                with path.open('rb') as src:
                    archive.addfile(member, src)
            else:
                assert member.isdir()  # No hardlink or symlink escapes.
                archive.addfile(member)
    observed = identity(archive_path)
    assert observed['sizeBytes'] <= 256 << 20
    manifest['inputs']['prepared-runtime.tar.gz'] = observed
    manifest['preparedExpandedBytes'] = expanded
    archive_path.chmod(0o444)
    with (args.output/'manifest.json').open('x') as out:
        json.dump(manifest, out, sort_keys=True)
    print(json.dumps(manifest, sort_keys=True))


if __name__ == '__main__':
    main()
