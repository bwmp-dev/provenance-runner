#!/usr/bin/env python3
"""Synthetic real systemd/loop proof; exclusively disposable privileged guest."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

spec = importlib.util.spec_from_file_location('boot', '/opt/measured-rootfs-boot.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=90).stdout.strip()


def pin(path):
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def write(path, data, mode=0o600):
    with path.open('xb') as output:
        output.write(data)
    path.chmod(mode)


def main():
    assert Path('/run/provenance-boot-disposable').read_text() == 'measured-boot-disposable-only\n'
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    run('groupadd', '--gid', '1994', 'boot-fixture')
    run('useradd', '--uid', '1994', '--gid', '1994', '--create-home',
        '--shell', '/usr/sbin/nologin', 'boot-fixture')
    # Ubuntu's minimal image otherwise reports the /etc/xdg alias first. Model
    # the actual hosted fragment path explicitly, without loosening the helper.
    manager = Path('/etc/systemd/system/user@1994.service.d')
    manager.mkdir()
    write(manager / 'fixture.conf',
          b'[Service]\nEnvironment=SYSTEMD_UNIT_PATH=/etc/systemd/user:/usr/lib/systemd/user\n', 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'user@1994.service')
    base = Path('/opt/boot-fixture')
    base.mkdir(mode=0o755)
    source = base / 'source'
    source.mkdir()
    write(source / 'fixture.txt', b'synthetic measured rootfs fixture\n', 0o444)
    image = base / 'source.squashfs'
    run('mksquashfs', str(source), str(image), '-noappend', '-no-recovery', '-processors', '1')
    digest = pin(image)['sha256']
    generation = base / ('sha256-' + digest)
    generation.mkdir(mode=0o710)
    os.chown(generation, 0, 1994)
    image.rename(generation / 'image.squashfs')
    image = generation / 'image.squashfs'
    image.chmod(0o440)
    os.chown(image, 0, 1994)
    root = generation / 'rootfs'
    root.mkdir()
    manifest = generation / 'image-manifest.json'
    # Synthetic fixture metadata exercises binding only, NOT real two-build proof.
    write(manifest, json.dumps({'format': 'squashfs-image-sha256/v1', 'sha256': digest,
                               'sizeBytes': image.stat().st_size, 'runnerUid': 1994,
                               'runnerGid': 1994, 'reproducibleBuilds': 2}).encode())
    userunit = Path('/etc/systemd/user/provenance-runner.service')
    write(userunit, b'[Service]\nExecStart=/usr/bin/sleep 3600\n', 0o644)
    p = {'version': 1, 'generation': str(generation), 'uid': 1994, 'gid': 1994,
         'image': pin(image), 'imageManifest': pin(manifest), 'rootfs': str(root),
         'loop': str(generation / 'loop'), 'userUnit': pin(userunit)}
    unit = Path('/etc/systemd/system') / run('systemd-escape', '--path', '--suffix=mount', str(root))
    write(unit, b.unit_bytes(p), 0o644)
    p['mountUnit'] = pin(unit)
    plan = base / 'plan.json'
    write(plan, json.dumps(p).encode())
    run('systemctl', 'daemon-reload')
    b.userctl(p, 'daemon-reload')
    command = ('python3', '-B', '/opt/measured-rootfs-boot.py')
    args = ('--plan', str(plan), '--plan-sha256', pin(plan)['sha256'])
    foreign = None
    try:
        wrong = subprocess.run((*command, 'ensure', '--plan', str(plan),
                                '--plan-sha256', '0' * 64), capture_output=True, timeout=90)
        assert wrong.returncode == 1 and not os.path.ismount(root)
        run(*command, 'ensure', *args)
        initial = b.mounted(p)
        loop = b.g.mount_info(root)['source']
        mapping = json.loads(run('losetup', '--json', '--list', '--output', 'AUTOCLEAR', loop))
        assert mapping['loopdevices'][0]['autoclear'] in (True, 1, '1')
        assert (root / 'fixture.txt').read_text() == 'synthetic measured rootfs fixture\n'
        run('runuser', '-u', 'boot-fixture', '--', 'python3', '-c',
            'import os,sys; f=os.open(sys.argv[1],os.O_RDONLY); os.close(f); '
            'f=os.open(sys.argv[2],os.O_RDONLY); os.close(f); '
            'assert open(sys.argv[3]).read()=="synthetic measured rootfs fixture\\n"',
            p['loop'], str(image), str(root / 'fixture.txt'))
        run(*command, 'ensure', *args)
        assert b.mounted(p) == initial
        b.userctl(p, 'start', userunit.name)
        run(*command, 'verify', *args)
        refused = subprocess.run((*command, 'ensure', *args), capture_output=True, timeout=90)
        assert refused.returncode == 1
        b.userctl(p, 'stop', userunit.name)
        run('systemctl', 'stop', unit.name)
        assert not os.path.ismount(root)
        assert run('losetup', '--associated', str(image)) == ''
        # Occupy a freshly allocated global loop with a different image, then put
        # its device number in our owned alias to simulate a stale reboot alias.
        other = base / 'unrelated.squashfs'
        write(other, image.read_bytes(), 0o400)
        foreign = run('losetup', '--find', '--show', '--read-only', str(other))
        foreign_device = b.loop_identity(foreign, other)
        alias = Path(p['loop'])
        alias.unlink()
        os.mknod(alias, stat.S_IFBLK | 0o440, foreign_device)
        os.chown(alias, 0, 1994)
        run(*command, 'ensure', *args)
        assert b.mounted(p) != foreign_device
        assert b.loop_identity(foreign, other) == foreign_device
        assert alias.stat().st_rdev == b.mounted(p)
        run(*command, 'verify', *args)
        print(json.dumps({'realSystemdMount': True, 'readonlyAutoclearVerified': True,
                          'idempotentEnsure': True, 'activeRunnerRefused': True,
                          'foreignLoopPreserved': True, 'stalePrivateAliasRepaired': True,
                          'rebootTested': False, 'productionAcceptance': False}))
    finally:
        b.userctl(p, 'stop', userunit.name)
        # Verify exact backing before cleanup; no force/lazy/global detaches.
        if os.path.ismount(root):
            b.mounted(p)
            run('systemctl', 'stop', unit.name)
        assert not os.path.ismount(root)
        assert run('losetup', '--associated', str(image)) == ''
        if foreign is not None:
            b.loop_identity(foreign, base / 'unrelated.squashfs')
            run('losetup', '--detach', foreign)
            assert run('losetup', '--associated', str(base / 'unrelated.squashfs')) == ''
        print(json.dumps({'ownedMountAndLoopsAbsent': True}))


if __name__ == '__main__':
    main()
