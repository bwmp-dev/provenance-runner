#!/usr/bin/env python3
"""Run only after the synthetic boot fixture, in its disposable systemd guest."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

spec = importlib.util.spec_from_file_location('selection', '/opt/measured-runtime-selection.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
b = s.b


def write(path, data, mode=0o600, gid=0):
    with path.open('xb') as f:
        f.write(data)
    path.chmod(mode)
    os.chown(path, 0, gid)


def pin(path):
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def rotation_fixture(root, evidence, previous, previous_path, legacy_plan):
    """Two actual immutable images; synthetic manifests/drain, never production."""
    source = evidence / 'rotation-source'
    source.mkdir()
    write(source / 'fixture.txt', b'second measured generation\n', 0o444)
    image = evidence / 'rotation.squashfs'
    b.run('mksquashfs', str(source), str(image), '-noappend', '-no-recovery', '-processors', '1')
    sha = pin(image)['sha256']
    generation = evidence / ('sha256-' + sha)
    generation.mkdir(mode=0o710)
    os.chown(generation, 0, previous['gid'])
    image.rename(generation / 'image.squashfs')
    image = generation / 'image.squashfs'
    image.chmod(0o440)
    os.chown(image, 0, previous['gid'])
    (generation / 'rootfs').mkdir()
    manifest = generation / 'image-manifest.json'
    write(manifest, json.dumps({'format': 'squashfs-image-sha256/v1', 'sha256': sha,
          'sizeBytes': image.stat().st_size, 'runnerUid': previous['uid'],
          'runnerGid': previous['gid'], 'reproducibleBuilds': 2}).encode())
    boot = previous | {'generation': str(generation), 'image': pin(image),
                      'imageManifest': pin(manifest), 'rootfs': str(generation / 'rootfs'),
                      'loop': str(generation / 'loop')}
    unit = Path('/etc/systemd/system') / b.run('systemd-escape', '--path', '--suffix=mount', boot['rootfs'])
    write(unit, b.unit_bytes(boot), 0o644)
    boot['mountUnit'] = pin(unit)
    bootpath = evidence / 'rotation-boot.json'
    write(bootpath, json.dumps(boot).encode())
    oldenv, oldhook = (root / 'runner.env').read_bytes(), (root / 'verify-rootfs').read_bytes()
    write(evidence / 'rotation-before.env', oldenv)
    write(evidence / 'rotation-after.env', b.render_environment(boot, oldenv))
    write(evidence / 'rotation-before.hook', oldhook)
    plan = legacy_plan | {'version': 2, 'bootPlan': pin(bootpath),
                         'previousBootPlan': pin(previous_path),
                         'environmentBefore': pin(evidence / 'rotation-before.env'),
                         'environmentAfter': pin(evidence / 'rotation-after.env'),
                         'hookBefore': pin(evidence / 'rotation-before.hook')}
    del plan['legacyRootfs']
    path = evidence / 'rotation.json'
    write(path, json.dumps(plan).encode())
    now = int(time.time())
    drain = evidence / 'rotation-drain.json'
    write(drain, json.dumps({'version': 1, 'planSha256': pin(path)['sha256'],
          'issuedAt': now, 'expiresAt': now + 300, 'platformDrainEvidenceSha256': 'c' * 64,
          'activeLeases': 0, 'pendingTerminalReplay': 0}).encode())
    b.run('systemctl', 'daemon-reload')
    def invoke(action, expected=0):
        result = subprocess.run(('python3', '-I', str(root / 'measured-runtime-selection.py'), action,
               '--plan', str(path), '--plan-sha256', pin(path)['sha256'], '--drain', str(drain),
               '--drain-sha256', pin(drain)['sha256']), capture_output=True, timeout=90, umask=0o077)
        assert result.returncode == expected, 'measured rotation invocation failed'
    try:
        # Both generation locks must independently exclude the operation.
        for lockpath in (previous['generation'], boot['generation']):
            fd = os.open(lockpath, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                invoke('select', 1)
            finally:
                os.close(fd)
        assert (root / 'runner.env').read_bytes() == oldenv
        assert (root / 'verify-rootfs').read_bytes() == oldhook
        b.run('systemctl', 'stop', Path(previous['mountUnit']['path']).name)
        invoke('select', 1)
        assert (root / 'runner.env').read_bytes() == oldenv
        assert (root / 'verify-rootfs').read_bytes() == oldhook
        b.execute(previous, 'ensure')
        # Interrupted selection is safe to resume; the mismatched hook refuses.
        (root / 'verify-rootfs').write_bytes(s.hook(plan))
        assert subprocess.run((str(root / 'verify-rootfs'),), capture_output=True,
                              timeout=90).returncode == 1
        invoke('select')
        invoke('select')
        b.run(str(root / 'verify-rootfs'))
        assert (Path(boot['rootfs']) / 'fixture.txt').read_bytes() == b'second measured generation\n'
        b.execute(previous, 'verify')
        # Drift in the pinned previous hook snapshot refuses before rollback.
        beforehook = Path(plan['hookBefore']['path'])
        beforehook.write_bytes(b'#!/bin/sh\nexit 0\n')
        invoke('rollback', 1)
        beforehook.write_bytes(oldhook)
        # Simulate committed rollback environment before restoring its hook.
        (root / 'runner.env').write_bytes(oldenv)
        assert subprocess.run((str(root / 'verify-rootfs'),), capture_output=True,
                              timeout=90).returncode == 1
        invoke('rollback')
        invoke('rollback')
        b.run(str(root / 'verify-rootfs'))
        assert (root / 'runner.env').read_bytes() == oldenv
        assert (root / 'verify-rootfs').read_bytes() == oldhook
        b.execute(boot, 'verify')
        print(json.dumps({'measuredRotationAndRollback': True, 'bothGenerationLocksEnforced': True,
                          'missingRollbackMountRefusedBeforeWrites': True,
                          'measuredMixedStateBootRefused': True, 'bothGenerationsRetained': True,
                          'productionDrainProven': False}))
    finally:
        if os.path.ismount(boot['rootfs']):
            b.mounted(boot)
            b.run('systemctl', 'stop', unit.name)
        assert not os.path.ismount(boot['rootfs'])
        assert b.run('losetup', '--associated', boot['image']['path']) == ''
        print(json.dumps({'rotationFixtureOwnedMountAndLoopAbsent': True}))


def main():
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert Path('/opt/boot-fixture/wrapper-proof.json').is_file()
    boot = json.loads(Path('/opt/boot-fixture/plan.json').read_text())
    b.quiet(boot)
    root = Path('/opt/provenance-runner')
    root.mkdir(mode=0o755)
    evidence = Path('/opt/boot-fixture/selection')
    evidence.mkdir(mode=0o700)
    for name in ('measured-runtime-selection.py', 'measured-rootfs-boot.py', 'runtime-generation.py'):
        write(root / name, (Path('/opt') / name).read_bytes(), 0o644)
    write(root / 'runsc', Path('/usr/bin/true').read_bytes(), 0o755)
    write(root / 'runner', Path('/usr/bin/sleep').read_bytes(), 0o755)
    legacy = root / 'rootfs'
    legacy.mkdir()
    write(legacy / 'legacy.txt', b'legacy synthetic fixture\n', 0o444)
    b.run('mount', '--bind', str(legacy), str(legacy))
    b.run('mount', '-o', 'remount,bind,ro,nosuid,nodev', str(legacy))
    tar = subprocess.run(('tar', '--sort=name', '--format=gnu', '--mtime=@0', '--owner=0',
                          '--group=0', '--numeric-owner', '-cf', '-', '-C', str(legacy), '.'),
                         check=True, capture_output=True, timeout=30).stdout
    tree = hashlib.sha256(tar).hexdigest()
    oldenv = ('PROVENANCE_RUNSC_PATH="/opt/provenance-runner/runsc-rootless"\n'
              'PROVENANCE_ROOTFS="/opt/provenance-runner/rootfs"\n'
              'PROVENANCE_ROOTFS_IDENTITY="sha256:' + tree + '"\n'
              'PROVENANCE_GVISOR_CGROUP_DRIVER="systemd-user"\n'
              'PROVENANCE_PAPER_CATALOGS_JSON="synthetic-catalog"\n').encode()
    oldhook = b'#!/bin/sh\nexit 0\n'
    write(root / 'runner.env', oldenv, 0o640, 1994)
    write(root / 'verify-rootfs', oldhook, 0o755)
    userunit = Path(boot['userUnit']['path'])
    # Fixture preparation, not a selector mutation: model fixed updater path.
    userunit.write_bytes(b'[Service]\nExecStart=/opt/provenance-runner/runner 3600\n'
                         b'EnvironmentFile=/opt/provenance-runner/runner.env\n')
    boot.update(version=2, runtimeEnvironment=str(root / 'runner.env'),
                runsc=pin(root / 'runsc'), userUnit=pin(userunit))
    bootpath = evidence / 'boot-plan.json'
    write(bootpath, json.dumps(boot).encode())
    for name in ('provenance-runner.service', 'provenance-runner-updater.service'):
        write(Path('/etc/systemd/system') / name,
              b'[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n', 0o644)
    (root / 'update-state').mkdir(mode=0o700)
    write(root / 'update-state/lock', b'')
    write(root / 'update-state/operation.json', b'{"phase":"complete"}')
    config = Path('/var/lib/provenance-runner/config')
    config.parent.mkdir(mode=0o755)
    config.mkdir(mode=0o700)
    os.chown(config, 1994, 1994)
    journal = config / '.provenance-runner-journal.json'
    write(journal, b'{"schemaVersion":"provenance.runner-journal/v1alpha1"}')
    os.chown(journal, 1994, 1994)
    write(evidence / 'before.env', oldenv)
    write(evidence / 'after.env', b.render_environment(boot, oldenv))
    write(evidence / 'before.hook', oldhook)
    plan = {'version': 1, 'bootPlan': pin(bootpath),
            'helper': pin(root / 'measured-rootfs-boot.py'),
            'generationHelper': pin(root / 'runtime-generation.py'),
            'wrapper': pin(Path('/etc/systemd/system/provenance-runner.service')),
            'updater': pin(Path('/etc/systemd/system/provenance-runner-updater.service')),
            'runner': pin(root / 'runner'), 'environmentBefore': pin(evidence / 'before.env'),
            'environmentAfter': pin(evidence / 'after.env'), 'hookBefore': pin(evidence / 'before.hook'),
            'legacyRootfs': {'path': str(legacy), 'treeSha256': tree}}
    planpath = evidence / 'selection.json'
    write(planpath, json.dumps(plan).encode())
    now = int(time.time())
    drainpath = evidence / 'drain.json'
    # Explicitly synthetic coordinator evidence, never a production drain claim.
    write(drainpath, json.dumps({'version': 1, 'planSha256': pin(planpath)['sha256'],
          'issuedAt': now, 'expiresAt': now + 300, 'platformDrainEvidenceSha256': 'b' * 64,
          'activeLeases': 0, 'pendingTerminalReplay': 0}).encode())
    b.run('systemctl', 'daemon-reload')
    b.userctl(boot, 'daemon-reload')
    command = ('python3', '-I', str(root / 'measured-runtime-selection.py'))
    args = ('--plan', str(planpath), '--plan-sha256', pin(planpath)['sha256'],
            '--drain', str(drainpath), '--drain-sha256', pin(drainpath)['sha256'])
    def invoke(action, expected=0):
        result = subprocess.run((*command, action, *args), capture_output=True, timeout=90,
                                umask=0o077)
        assert result.returncode == expected, 'selection fixture invocation failed'
        assert (root / 'runner.env').stat().st_mode & 0o7777 == 0o640
        assert (root / 'verify-rootfs').stat().st_mode & 0o7777 == 0o755
    original_runner = pin(root / 'runner')
    try:
        (root / 'update-state/operation.json').write_bytes(b'{"phase":"rollback"}')
        invoke('select', 1)
        (root / 'update-state/operation.json').write_bytes(b'{"phase":"complete"}')
        journal.write_bytes(b'{"schemaVersion":"provenance.runner-journal/v1alpha1","pendingMessage":"eA=="}')
        invoke('select', 1)
        journal.write_bytes(b'{"schemaVersion":"provenance.runner-journal/v1alpha1"}')
        with (root / 'update-state/lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            invoke('select', 1)
        assert (root / 'runner.env').read_bytes() == oldenv
        # Model an interrupted first replacement: new hook + old environment.
        (root / 'verify-rootfs').write_bytes(s.hook(plan))
        guard = subprocess.run((str(root / 'verify-rootfs'),), capture_output=True, timeout=90)
        assert guard.returncode == 1 and not os.path.ismount(boot['rootfs'])
        invoke('select')
        b.selected_environment(boot)
        b.execute(boot, 'verify')
        invoke('select')
        b.run(str(root / 'verify-rootfs'))
        b.userctl(boot, 'start', userunit.name)
        invoke('rollback', 1)
        b.userctl(boot, 'stop', userunit.name)
        selected = (root / 'runner.env').read_bytes()
        (root / 'runner.env').write_bytes(selected.replace(b'synthetic-catalog', b'updated-catalog'))
        # Future catalog changes keep the boot binding valid, but the old full
        # snapshot may not erase them during rollback without a new review.
        b.run(str(root / 'verify-rootfs'))
        invoke('rollback', 1)
        (root / 'runner.env').write_bytes(selected)
        invoke('rollback')
        invoke('rollback')
        assert (root / 'runner.env').read_bytes() == oldenv
        assert (root / 'verify-rootfs').read_bytes() == oldhook
        assert pin(root / 'runner') == original_runner
        assert pin(userunit) == boot['userUnit']
        # Exercise both replacements from the original state, not only the
        # interrupted-hook state above, with the production operator umask.
        invoke('select')
        rotation_fixture(root, evidence, boot, bootpath, plan)
        invoke('rollback')
        assert (root / 'runner.env').read_bytes() == oldenv
        assert (root / 'verify-rootfs').read_bytes() == oldhook
        print(json.dumps({'realSelectionAndRollback': True, 'updaterLockExclusion': True,
                          'mixedStateBootRefused': True, 'activeRunnerRollbackRefused': True,
                          'pendingUpdaterAndTerminalRefused': True, 'catalogUpdatePreserved': True,
                          'originalBytesRestored': True, 'fixedRunnerAndUserUnitUnchanged': True,
                          'restrictiveUmaskModesPreserved': True,
                          'productionDrainProven': False, 'realSignedUpdaterTested': False}))
    finally:
        b.userctl(boot, 'stop', userunit.name)
        if os.path.ismount(boot['rootfs']):
            b.mounted(boot)
            b.run('systemctl', 'stop', Path(boot['mountUnit']['path']).name)
        assert not os.path.ismount(boot['rootfs'])
        assert b.run('losetup', '--associated', boot['image']['path']) == ''
        s.g.legacy({'legacyRootfs': plan['legacyRootfs']})
        b.run('umount', str(legacy))
        assert not os.path.ismount(legacy)
        print(json.dumps({'selectionFixtureOwnedMountsAndLoopsAbsent': True}))


if __name__ == '__main__':
    main()
