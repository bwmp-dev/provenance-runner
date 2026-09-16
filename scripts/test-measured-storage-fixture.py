#!/usr/bin/env python3
"""Synthetic fixed-size disk tests, only in the disposable systemd guest."""
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

spec = importlib.util.spec_from_file_location('storage', '/opt/measured-storage.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
b = s.b
BASE = Path('/opt/storage-fixture')


def write(path, data, mode=0o600):
    with path.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    path.chmod(mode)


def pin(path):
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def invoke(action, expected=0):
    path = BASE / 'plan.json'
    result = subprocess.run(('python3', '-I', '/opt/measured-storage.py', action,
           '--plan', str(path), '--plan-sha256', pin(path)['sha256']),
           capture_output=True, timeout=90, umask=0o077)
    assert result.returncode == expected, 'bounded storage invocation failed'


def main():
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert Path('/.dockerenv').is_file()
    action = sys.argv[1]
    if action == 'prepare':
        assert Path('/run/provenance-boot-disposable').read_text() == 'measured-boot-disposable-only\n'
        BASE.mkdir(mode=0o700)
        image = BASE / 'disk.ext4'
        fd = os.open(image, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.posix_fallocate(fd, 0, 64 << 20)
            os.fsync(fd)
        finally:
            os.close(fd)
        # Only this fixture formats its exclusively created synthetic file.
        b.run('mkfs.ext4', '-q', '-N', '1024', '-E',
              'nodiscard,lazy_itable_init=0,lazy_journal_init=0', str(image))
        root = BASE / 'data'
        root.mkdir(mode=0o711)
        b.run('mount', '-t', 'ext4', '-o', 'loop,rw,nosuid,nodev,noexec', str(image), str(root))
        root.chmod(0o711)
        b.run('umount', str(root))
        info = image.stat()
        with image.open('rb') as f:
            f.seek(1024)
            geometry = s.geometry(f.read(1024))
        p = {'version': 1, 'backing': {'path': str(image), 'device': info.st_dev,
             'inode': info.st_ino, **geometry}, 'mountpoint': str(root)}
        unit = Path('/etc/systemd/system') / b.run('systemd-escape', '--path', '--suffix=mount', str(root))
        write(unit, s.unit_bytes(p), 0o644)
        p['mountUnit'] = pin(unit)
        write(BASE / 'plan.json', json.dumps(p).encode())
        b.run('systemctl', 'daemon-reload')
        invoke('verify', 1)
        # Never hide existing data under the mount.
        write(root / 'obstruction', b'synthetic')
        invoke('ensure', 1)
        (root / 'obstruction').unlink()
        with image.open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            invoke('ensure', 1)
        image.chmod(0o640)
        invoke('ensure', 1)
        image.chmod(0o600)
        invoke('ensure')
        invoke('ensure')
        write(root / 'durable', b'bounded persistent fixture\n')
        full = root / 'fill'
        reached = False
        try:
            with full.open('xb', buffering=0) as f:
                for _ in range(65):
                    f.write(b'x' * (1 << 20))
                os.fsync(f.fileno())
        except OSError as error:
            assert error.errno == errno.ENOSPC
            reached = True
        assert reached and full.stat().st_size <= 64 << 20
        full.unlink()
        inode_root = root / 'inode-limit'
        inode_root.mkdir()
        reached_inodes = False
        try:
            for index in range(p['backing']['inodes'] + 1):
                with (inode_root / str(index)).open('xb'):
                    pass
        except OSError as error:
            assert error.errno == errno.ENOSPC
            reached_inodes = True
        assert reached_inodes and os.statvfs(root).f_ffree == 0
        for child in inode_root.iterdir():
            assert child.is_file() and child.name.isdecimal()
            child.unlink()
        inode_root.rmdir()
        invoke('verify')
        # Explicit plan drift cannot silently reuse the existing filesystem.
        original = (BASE / 'plan.json').read_bytes()
        for changed in ({'inode': info.st_ino + 1}, {'sizeBytes': 128 << 20},
                        {'uuid': '00000000-0000-0000-0000-000000000000'}):
            altered = p | {'backing': p['backing'] | changed}
            (BASE / 'plan.json').write_bytes(json.dumps(altered).encode())
            invoke('verify', 1)
        (BASE / 'plan.json').write_bytes(original)
        invoke('verify')
        print(json.dumps({'boundedStorageENOSPC': True, 'boundedStorageInodeENOSPC': True,
                          'storageIdentityDriftRefused': True,
                          'nonemptyMountpointRefused': True, 'backingLockEnforced': True,
                          'sizeBytes': 64 << 20, 'productionProvisioned': False}))
    else:
        assert action == 'verify-cleanup'
        p = json.loads((BASE / 'plan.json').read_text())
        try:
            assert not os.path.ismount(p['mountpoint'])
            invoke('ensure')
            invoke('verify')
            assert (Path(p['mountpoint']) / 'durable').read_bytes() == b'bounded persistent fixture\n'
            print(json.dumps({'boundedStorageFreshSystemdRestore': True, 'persistentBytesPreserved': True,
                              'kernelHostRebootTested': False}))
        finally:
            if os.path.ismount(p['mountpoint']):
                s.mounted(p)
                b.run('systemctl', 'stop', Path(p['mountUnit']['path']).name)
            assert not os.path.ismount(p['mountpoint'])
            assert b.run('losetup', '--associated', p['backing']['path']) == ''
            print(json.dumps({'boundedStorageOwnedMountAndLoopAbsent': True}))


if __name__ == '__main__':
    main()
