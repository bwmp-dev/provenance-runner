#!/usr/bin/env python3
"""Actual hosted launcher/daemon readiness in an exclusively disposable guest."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

spec = importlib.util.spec_from_file_location('launch', '/opt/measured-service-launch.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
b, g = s.b, s.g


def write(path, data, mode=0o600, gid=0):
    with path.open('xb') as file:
        file.write(data)
    path.chmod(mode)
    os.chown(path, 0, gid)


def directory(path, mode=0o755, gid=0):
    path.mkdir(mode=mode)
    path.chmod(mode)
    os.chown(path, 0, gid)


def copy(source, target, mode=0o600, gid=0):
    with source.open('rb') as src, target.open('xb') as dst:
        shutil.copyfileobj(src, dst)
    target.chmod(mode)
    os.chown(target, 0, gid)


def pin(path):
    return {'path': str(path), 'sha256': g.fingerprint(path)['sha256']}


def main():
    assert os.geteuid() == 0 and Path('/.dockerenv').is_file()
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert Path('/run/provenance-daemon-disposable').read_text() == 'hosted-daemon-disposable-only\n'
    b.run('groupadd', '--gid', '981', 'provenance-worker')
    b.run('useradd', '--system', '--no-create-home', '--uid', '994', '--gid', '981',
          '--shell', '/usr/sbin/nologin', 'provenance-worker')
    for name, identity in s.ROLES.items():
        b.run('groupadd', '--gid', str(identity), name)
        b.run('useradd', '--system', '--no-create-home', '--no-log-init', '--uid', str(identity),
              '--gid', name, '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', name)
    s.UPLINK_LINK.parent.mkdir(parents=True, exist_ok=True)
    s.UPLINK_LINK.write_bytes(s.uplink_link_bytes())
    s.UPLINK_LINK.chmod(0o644)
    directory(s.ROOT)
    directory(s.PLAN.parent)
    for name in ('measured-service-launch.py', 'measured-rootfs-boot.py', 'runtime-generation.py',
                 'measured-storage.py', 'measured-host-inventory.py'):
        copy(Path('/opt') / name, s.ROOT / name, 0o644)
    copy(Path('/inputs/runner'), s.ROOT / 'runner', 0o755)
    copy(Path('/runsc-input'), s.ROOT / 'runsc', 0o755)
    copy(Path('/inputs/client.test'), Path('/opt/client.test'), 0o755)
    directory(s.ROOT / 'measured')
    manifest = json.loads(Path('/manifest-input').read_text())
    assert manifest['runnerUid'] == 994 and manifest['runnerGid'] == 981 and manifest['reproducibleBuilds'] == 2
    generation = s.ROOT / 'measured' / ('sha256-' + manifest['sha256'])
    directory(generation, 0o710, 981)
    copy(Path('/rootfs-input'), generation / 'image.squashfs', 0o440, 981)
    copy(Path('/manifest-input'), generation / 'image-manifest.json')
    assert pin(generation / 'image.squashfs')['sha256'] == manifest['sha256']
    directory(generation / 'rootfs')
    userunit = Path('/etc/systemd/user/provenance-runner.service')
    write(userunit, b'[Service]\nExecStart=/usr/bin/sleep 3600\n', 0o644)
    boot = {'version': 2, 'uid': 994, 'gid': 981, 'generation': str(generation),
            'rootfs': str(generation / 'rootfs'), 'loop': str(generation / 'loop'),
            'image': pin(generation / 'image.squashfs'),
            'imageManifest': pin(generation / 'image-manifest.json'), 'userUnit': pin(userunit),
            'runtimeEnvironment': str(s.ROOT / 'runner.env'), 'runsc': pin(s.ROOT / 'runsc')}
    imageunit = Path('/etc/systemd/system') / b.run('systemd-escape', '--path', '--suffix=mount', boot['rootfs'])
    write(imageunit, b.unit_bytes(boot), 0o644)
    boot['mountUnit'] = pin(imageunit)
    bootpath = s.PLAN.parent / 'boot.json'
    write(bootpath, json.dumps(boot).encode())
    write(s.ROOT / 'runner.env', b.render_environment(boot, b'FIXTURE_ONLY=1\n'), 0o640, 981)
    manager = Path('/etc/systemd/system/user@994.service.d')
    directory(manager)
    write(manager / 'fixture.conf', b'[Service]\nEnvironment=SYSTEMD_UNIT_PATH=/etc/systemd/user:/usr/lib/systemd/user\n', 0o644)
    directory(s.DATA.parent, 0o711)
    directory(s.DATA, 0o711)
    diskfile = s.DATA.parent / 'storage.ext4'
    fd = os.open(diskfile, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.posix_fallocate(fd, 0, 8 << 30)
        os.fsync(fd)
    finally:
        os.close(fd)
    b.run('mkfs.ext4', '-q', '-b', '4096', '-N', '524288', '-m', '0', '-E',
          'nodiscard,lazy_itable_init=0,lazy_journal_init=0', str(diskfile))
    b.run('debugfs', '-w', '-R', 'set_inode_field <2> mode 040711', str(diskfile))
    info = diskfile.stat()
    with diskfile.open('rb') as file:
        file.seek(1024)
        geometry = s.storage.geometry(file.read(1024))
    disk = {'version': 1, 'mountpoint': str(s.DATA), 'backing': {'path': str(diskfile),
            'device': info.st_dev, 'inode': info.st_ino, **geometry}}
    diskunit = Path('/etc/systemd/system') / b.run('systemd-escape', '--path', '--suffix=mount', str(s.DATA))
    write(diskunit, s.storage.unit_bytes(disk), 0o644)
    disk['mountUnit'] = pin(diskunit)
    diskpath = s.PLAN.parent / 'storage.json'
    write(diskpath, json.dumps(disk).encode())
    secretunit = Path('/etc/systemd/system') / b.run('systemd-escape', '--path', '--suffix=mount', str(s.SECRET))
    write(secretunit, s.secret_unit_bytes(), 0o644)
    service = Path('/etc/systemd/system/provenance-measured.service')
    write(service, s.unit_bytes(boot, disk, {'mountUnit': pin(secretunit)}), 0o644)
    b.run('systemctl', 'daemon-reload')
    b.run('systemctl', 'start', 'user@994.service')
    b.userctl(boot, 'daemon-reload')
    b.execute(boot, 'ensure')
    s.storage.execute(disk, 'ensure')
    for name, mode in (('bundles', 0o711), ('cgroups', 0o700), ('bundle-journal', 0o700), ('uplinks', 0o700)):
        directory(s.DATA / name, mode)
    config = {'version': 1, 'workerUid': 994, 'workerGid': 981,
        'cgroupParent': str(s.CGROUP / 'jobs'), 'bundleRoot': str(s.DATA / 'bundles'),
        'cgroupState': str(s.DATA / 'cgroups'), 'bundleState': str(s.DATA / 'bundle-journal'),
        'uplinkState': str(s.DATA / 'uplinks'), 'secretRoot': str(s.SECRET),
        'socketDirectory': str(s.RUN / 'socket'), 'sandboxPath': boot['runsc']['path'],
        'rootPath': boot['rootfs'], 'imagePath': boot['image']['path'], 'loopPath': boot['loop'],
        'runnerSha256': pin(s.ROOT / 'runner')['sha256'], 'sandboxSha256': boot['runsc']['sha256'],
        'rootfsSha256': boot['image']['sha256'],
        'ip': pin(Path(shutil.which('ip')).resolve()), 'nft': pin(Path(shutil.which('nft')).resolve()),
        'nsenter': pin(Path(shutil.which('nsenter')).resolve()),
        'workload': {'UID': 262144, 'GID': 262144, 'OverflowUID': 262145, 'OverflowGID': 262145},
        'router': {'UID': 262146, 'GID': 262146, 'OverflowUID': 262147, 'OverflowGID': 262147},
        'runtimeOrigin': 'https://fixtures.example.com', 'runtimePublicKey': '01' * 32,
        'resolver': '9.9.9.9:53', 'sensitiveNetworks': ['203.0.113.0/24'],
        'maximumTtlSeconds': 20, 'maximumInputBytes': 64 << 20,
        'maximumPolicy': {'sandbox': 'SANDBOX_KIND_GVISOR', 'requirement': 'ENVIRONMENT_REQUIREMENT_REQUIRED',
            'resources': {'cpuMillis': 1000, 'memoryBytes': str(128 << 20), 'diskBytes': str(256 << 20), 'processCount': 64},
            'preparationTimeout': '20s', 'executionTimeout': '20s', 'gracefulShutdownTimeout': '1s',
            'networkV2': {'mode': 'NETWORK_MODE_ALLOWLIST', 'maximumConnections': 8, 'maximumBytesPerSecond': '65536',
                'permissions': [{'hostname': 'example.com', 'port': 443, 'transport': 'NETWORK_TRANSPORT_V2_TCP'}]}}}
    configpath = s.PLAN.parent / 'measured-service.json'
    write(configpath, json.dumps(config).encode())
    plan = {'version': 1, 'runner': pin(s.ROOT / 'runner'), 'config': pin(configpath),
        'bootPlan': pin(bootpath), 'storagePlan': pin(diskpath), 'unit': pin(service),
        'secretMount': pin(secretunit), 'launcher': pin(s.ROOT / 'measured-service-launch.py'),
        'bootHelper': pin(s.ROOT / 'measured-rootfs-boot.py'),
        'generationHelper': pin(s.ROOT / 'runtime-generation.py'),
        'storageHelper': pin(s.ROOT / 'measured-storage.py'),
        'inventoryHelper': pin(s.ROOT / 'measured-host-inventory.py')}
    write(s.PLAN, json.dumps(plan).encode())
    try:
        for _ in range(3):
            b.run('systemctl', 'stop', 'user@994.service')
            # Model cold-boot mount ordering, not only a warm daemon restart.
            # The private alias deliberately names an unrelated device number;
            # no global loop node/backing is touched or opened through it.
            for mount, target, backing in ((secretunit, str(s.SECRET), None),
                                           (imageunit, boot['rootfs'], boot['image']['path']),
                                           (diskunit, disk['mountpoint'], disk['backing']['path'])):
                b.run('systemctl', 'stop', mount.name)
                assert not os.path.ismount(target)
                if backing:
                    assert b.run('losetup', '--associated', backing) == ''
            stale = generation / '.fixture-stale-loop'
            os.mknod(stale, stat.S_IFBLK | 0o440, os.makedev(7, 1048575))
            os.chown(stale, 0, 981)
            stale.chmod(0o440)
            os.replace(stale, Path(boot['loop']))
            b.run('systemctl', 'start', service.name)
            assert b.run('systemctl', 'show', service.name, '--property=ActiveState', '--value') == 'active'
            assert Path(boot['loop']).stat().st_rdev != os.makedev(7, 1048575)
            assert b.run('systemctl', 'is-active', 'user@994.service') == 'active'
            b.execute(boot, 'verify')
            result = b.run('runuser', '-u', 'provenance-worker', '--', 'env',
                'PROVENANCE_DISPOSABLE_HOSTED_DAEMON=1', '/opt/client.test', '-test.v',
                '-test.run=^TestHostedMeasuredSystemdReadiness$', '-test.count=1')
            assert '--- PASS: TestHostedMeasuredSystemdReadiness ' in result and 'SKIP' not in result
            print(result, flush=True)
            b.run('systemctl', 'stop', service.name)
            assert not (s.RUN / 'socket/control.sock').exists()
            assert not list((s.DATA / 'bundles').iterdir())
            for name in ('cgroups', 'bundle-journal', 'uplinks'):
                assert [p.name for p in (s.DATA / name).iterdir()] == ['.lock']
        if os.environ.get('PROVENANCE_DISPOSABLE_MEASURED_UPDATER') == '1':
            updater_spec = importlib.util.spec_from_file_location('updater_fixture', '/opt/test-measured-updater-systemd-fixture.py')
            updater_fixture = importlib.util.module_from_spec(updater_spec)
            updater_spec.loader.exec_module(updater_fixture)
            updater_fixture.exercise()
        print(json.dumps({'actualHostedDaemonReadinessAndRestart': True, 'workerUid': 994,
            'repetitions': 3, 'rootImageSha256': manifest['sha256'],
            'coldMountStartAndStaleLoopAliasRepaired': True,
            'workerManagerDependencyRestored': True,
            'privateGatewayCredentialsLoaded': False, 'jobExecutionTested': False,
            'productionActivation': False}), flush=True)
    except Exception:
        print(b.run('journalctl', '-b', '-u', service.name, '--no-pager', '-n', '40', '-o', 'cat')[-8192:], flush=True)
        raise
    finally:
        b.run('systemctl', 'stop', service.name)
        for unit, target, image in ((secretunit, str(s.SECRET), None),
                                    (imageunit, boot['rootfs'], boot['image']['path']),
                                    (diskunit, disk['mountpoint'], disk['backing']['path'])):
            b.run('systemctl', 'stop', unit.name)
            assert not os.path.ismount(target)
            if image:
                assert b.run('losetup', '--associated', image) == ''
        assert not s.CGROUP.exists()
        print(json.dumps({'hostedDaemonOwnedMountsLoopsAndGroupsAbsent': True}), flush=True)


if __name__ == '__main__':
    main()
