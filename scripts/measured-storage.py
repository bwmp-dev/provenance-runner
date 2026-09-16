#!/usr/bin/env python3
"""Verify/restore preprovisioned bounded storage. Never format, resize or detach."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import uuid

spec = importlib.util.spec_from_file_location('boot', Path(__file__).with_name('measured-rootfs-boot.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
g, require = b.g, b.require


def unit_bytes(p):
    return ('[Unit]\nDescription=Provenance bounded persistent staging\n\n[Mount]\nWhat=' +
            p['backing']['path'] + '\nWhere=' + p['mountpoint'] +
            '\nType=ext4\nOptions=loop,rw,nosuid,nodev,noexec\nTimeoutSec=60\n').encode()


def geometry(raw):
    require(len(raw) == 1024 and struct.unpack_from('<H', raw, 56)[0] == 0xef53,
            'ext filesystem superblock')
    require(struct.unpack_from('<I', raw, 92)[0] & 0x4 and
            struct.unpack_from('<I', raw, 96)[0] & 0x40, 'journalled extent filesystem required')
    log = struct.unpack_from('<I', raw, 24)[0]
    require(log in (0, 1, 2), 'filesystem block size')
    blocks = struct.unpack_from('<I', raw, 4)[0]
    if struct.unpack_from('<I', raw, 96)[0] & 0x80:
        blocks |= struct.unpack_from('<I', raw, 336)[0] << 32
    return {'sizeBytes': blocks * (1024 << log), 'blockBytes': 1024 << log,
            'inodes': struct.unpack_from('<I', raw, 0)[0],
            'uuid': str(uuid.UUID(bytes=bytes(raw[104:120])))}


def backing(p):
    item = p['backing']
    path = g.protected(item['path'])
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_gid == 0 and info.st_nlink == 1 and
                (info.st_dev, info.st_ino, info.st_size) ==
                (item['device'], item['inode'], item['sizeBytes']) and
                info.st_blocks * 512 >= info.st_size, 'backing identity/allocation drift')
        actual = geometry(os.pread(fd, 1024, 1024))
        require(all(actual[k] == item[k] for k in ('sizeBytes', 'blockBytes', 'inodes', 'uuid')),
                'filesystem geometry drift')
        return info
    finally:
        os.close(fd)


def load(path, digest):
    p = g.read_json(path, digest)
    require(isinstance(p, dict) and set(p) == {'version', 'backing', 'mountpoint', 'mountUnit'},
            'storage plan fields')
    require(type(p['version']) is int and p['version'] == 1, 'storage plan version')
    item = p['backing']
    require(isinstance(item, dict) and set(item) ==
            {'path', 'device', 'inode', 'sizeBytes', 'blockBytes', 'inodes', 'uuid'}, 'backing fields')
    b.safe_path(item['path'])
    mountpoint = b.safe_path(p['mountpoint'])
    require(Path(item['path']) != mountpoint and mountpoint not in Path(item['path']).parents,
            'backing inside managed mount')
    require(all(type(item[k]) is int and item[k] > 0 for k in
                ('device', 'inode', 'sizeBytes', 'blockBytes', 'inodes')) and
            64 << 20 <= item['sizeBytes'] <= 16 << 30 and item['blockBytes'] in (1024, 2048, 4096) and
            1024 <= item['inodes'] <= 1048576 and isinstance(item['uuid'], str) and
            re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', item['uuid']),
            'bounded backing geometry')
    unit = p['mountUnit']
    require(isinstance(unit, dict) and set(unit) == {'path', 'sha256'} and
            isinstance(unit['sha256'], str) and re.fullmatch('[a-f0-9]{64}', unit['sha256']),
            'mount unit pin')
    b.safe_path(unit['path'], mount_unit=True)
    require(unit['path'] == '/etc/systemd/system/' +
            b.run('systemd-escape', '--path', '--suffix=mount', p['mountpoint']), 'mount unit name')
    g.fingerprint(unit['path'], unit['sha256'])
    require(Path(unit['path']).read_bytes() == unit_bytes(p), 'mount unit content')
    require(mountpoint not in Path(unit['path']).parents and mountpoint not in Path(path).parents,
            'control inputs inside managed mount')
    backing(p)
    return p


def mounted(p):
    source = backing(p)
    m = g.mount_info(p['mountpoint'])
    require(m['fstype'] == 'ext4' and
            {'rw', 'nosuid', 'nodev', 'noexec'} <= set(m['options'].split(',')), 'storage mount flags')
    require(re.fullmatch('/dev/loop[0-9]+', m['source']), 'storage loop source')
    fd = os.open(m['source'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        node = os.fstat(fd)
        raw = bytearray(232)
        fcntl.ioctl(fd, 0x4c05, raw, True)
        info = struct.unpack('=QQQQQIIII64s64s32sQQ', raw)
        require(stat.S_ISBLK(node.st_mode) and os.major(node.st_rdev) == 7 and
                os.minor(node.st_rdev) == info[5] and (info[0], info[1]) == (source.st_dev, source.st_ino)
                and info[3:5] == (0, 0) and info[6:8] == (0, 0) and info[8] == 4,
                'storage loop backing/flags')  # RW, AUTOCLEAR; no offset/size override/encryption.
        require(m['maj:min'] == f'{os.major(node.st_rdev)}:{os.minor(node.st_rdev)}',
                'storage mount device')
    finally:
        os.close(fd)
    require(b.run('findmnt', '--submounts', '--raw', '--noheadings', '--output', 'TARGET',
                  '--mountpoint', p['mountpoint']).splitlines() == [p['mountpoint']], 'nested storage mount')
    root = g.protected(p['mountpoint'], True).stat()
    require(root.st_gid == 0 and stat.S_IMODE(root.st_mode) == 0o711, 'storage root custody')
    usage = os.statvfs(p['mountpoint'])
    require(usage.f_frsize == p['backing']['blockBytes'] and
            usage.f_blocks * usage.f_frsize <= p['backing']['sizeBytes'] and
            usage.f_files == p['backing']['inodes'], 'mounted storage capacity')


def execute(p, action):
    backing(p)
    b.loaded_unit(p, 'mountUnit', lambda *args: b.run('systemctl', *args))
    if action == 'ensure':
        unit = Path(p['mountUnit']['path']).name
        state = b.run('systemctl', 'show', unit, '--property=ActiveState', '--value')
        require(state in ('active', 'inactive', 'failed'), 'storage mount transition')
        if state != 'active':
            require(not os.path.ismount(p['mountpoint']), 'unmanaged storage mount')
            root = g.protected(p['mountpoint'], True)
            require(root.stat().st_gid == 0 and stat.S_IMODE(root.stat().st_mode) == 0o711 and
                    not any(root.iterdir()), 'nonempty/unprotected storage mountpoint')
            b.run('systemctl', 'start', unit)
    mounted(p)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('ensure', 'verify'))
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0 and re.fullmatch('[a-f0-9]{64}', args.plan_sha256), 'root and digest required')
    os.environ.clear()
    os.environ.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C')
    p = load(args.plan, args.plan_sha256)
    fd = os.open(p['backing']['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        p = load(args.plan, args.plan_sha256)
        require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) ==
                (p['backing']['device'], p['backing']['inode']), 'locked backing drift')
        execute(p, args.action)
    finally:
        os.close(fd)
    print(json.dumps({'verified': True, 'sizeBytes': p['backing']['sizeBytes'],
                      'inodes': p['backing']['inodes'], 'formatted': False, 'serviceStarted': False}))


if __name__ == '__main__':
    try:
        main()
    except (g.Refusal, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('measured storage refused; preserve state for inspection', file=sys.stderr)
        sys.exit(1)
