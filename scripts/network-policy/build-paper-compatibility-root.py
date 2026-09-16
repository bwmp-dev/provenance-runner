#!/usr/bin/env python3
"""Disposable build-only fixture: accepted Ubuntu source plus exact Paper helper.

No execution service, credential loading, host installation or image activation.
The caller supplies private /opt/provenance-paper-fixture-build tmpfs and fresh
/outputs storage, with read-only /repo, /inputs and /builder mounts.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

OCI = 'ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517'
SOURCE = 'aa01a6fc293b28fac1269ba38fb76b67a939bc5a4d313fa1a2fdfe95518b0e3d'
NORMALIZED = 'c9a44780f9e5ae2d33be83a1a5b69c8fc95fddc99d86d327b74f6adaaab08095'
BUILDER = '47d5c1af3da11864e64c9dc6bb4e568719dcc315e6a744e79381ce3374fb7393'
WORK = Path('/opt/provenance-paper-fixture-build')


def digest(path):
    with open(path, 'rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def call(*args, env=None):
    return subprocess.check_output(args, text=True, env=env, timeout=300).strip()


def main():
    assert os.geteuid() == 0 and Path('/.dockerenv').is_file()
    assert len(sys.argv) == 2 and re.fullmatch('[a-f0-9]{64}', sys.argv[1])
    assert WORK.is_dir() and not WORK.is_symlink() and not list(WORK.iterdir())
    assert WORK.stat().st_uid == 0 and WORK.stat().st_mode & 0o777 == 0o700
    assert digest('/inputs/source.tar') == SOURCE
    assert digest('/inputs/paper-helper') == sys.argv[1]
    assert digest('/builder/mksquashfs') == BUILDER
    root = WORK/'source'
    root.mkdir(mode=0o700)
    # This is the exact pinned OCI export, not a customer archive. The existing
    # normalizer independently verifies the full accepted prepared-tree hash.
    subprocess.run(['tar', '-xf', '/inputs/source.tar', '-C', str(root)], check=True, timeout=60)
    prepare = '/repo/scripts/prepare-gvisor-rootfs.sh'
    try:
        call('bash', prepare, 'prepare', str(root))
        source = json.loads(call('python3', '/repo/scripts/prepare-ubuntu-measured-source.py',
                                 '--root', str(root), '--output', str(WORK/'normalized.tar'), '--source-oci', OCI))
        assert source['archiveSha256'] == NORMALIZED and source['sourceUnchanged']
        manifest = json.loads(call('python3', '/repo/scripts/build-measured-rootfs.py',
                                  '--source', str(WORK/'normalized.tar'), '--source-sha256', NORMALIZED,
                                  '--builder', '/builder/mksquashfs', '--builder-sha256', BUILDER,
                                  '--paper-guest', '/inputs/paper-helper', '--paper-guest-sha256', sys.argv[1],
                                  '--uid', '65532', '--gid', '65532', '--output', str(WORK/'built'),
                                  env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LD_LIBRARY_PATH': '/builder/lib'}))
        assert manifest['reproducibleBuilds'] == 2 and manifest['paperGuestSha256'] == sys.argv[1]
        source_image = WORK/'built'/('sha256-'+manifest['sha256']+'.squashfs')
        assert digest(source_image) == manifest['sha256']
        with open('/outputs/rootfs.squashfs', 'xb') as out, source_image.open('rb') as source_file:
            shutil.copyfileobj(source_file, out, 1 << 16)
            out.flush()
            os.fsync(out.fileno())
        os.chmod('/outputs/rootfs.squashfs', 0o444)
        print(json.dumps(manifest, sort_keys=True))
    finally:
        if subprocess.run(['mountpoint', '-q', str(root)]).returncode == 0:
            subprocess.run(['bash', prepare, 'release', str(root)], check=True, timeout=30)


if __name__ == '__main__':
    main()
