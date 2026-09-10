#!/usr/bin/env python3
"""Drained hosted environment/hook selection. Never starts/stops the runner.

Install protected artifacts and mount-unit metadata separately. This operator
entrypoint preserves the fixed signed-updater binary path and credentials.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('boot', Path(__file__).with_name('measured-rootfs-boot.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
g, require = b.g, b.require
ROOT = Path('/opt/provenance-runner')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hook(p):
    return ('#!/bin/sh\nset -eu\nexec /usr/bin/python3 -I ' + p['helper']['path'] +
            ' ensure --plan ' + p['bootPlan']['path'] + ' --plan-sha256 ' +
            p['bootPlan']['sha256'] + '\n').encode()


def load(path, sha):
    p = g.read_json(path, sha)
    require(isinstance(p, dict), 'selection plan object')
    require(set(p) == {'version', 'bootPlan', 'helper', 'generationHelper', 'wrapper',
                       'updater', 'runner', 'environmentBefore', 'environmentAfter',
                       'hookBefore', 'legacyRootfs'}, 'selection plan fields')
    require(type(p['version']) is int and p['version'] == 1, 'selection plan version')
    pins = ('bootPlan', 'helper', 'generationHelper', 'wrapper', 'updater', 'runner',
            'environmentBefore', 'environmentAfter', 'hookBefore')
    paths = []
    for name in pins:
        item = p[name]
        require(isinstance(item, dict) and set(item) == {'path', 'sha256'} and
                isinstance(item['sha256'], str) and
                re.fullmatch('[a-f0-9]{64}', item['sha256']), 'selection pin')
        b.safe_path(item['path'])
        g.fingerprint(item['path'], item['sha256'], name == 'runner')
        paths.append(item['path'])
    require(len(set(paths)) == len(paths), 'overlapping selection inputs')
    for name, expected in (
            ('helper', str(ROOT / 'measured-rootfs-boot.py')),
            ('generationHelper', str(ROOT / 'runtime-generation.py')),
            ('runner', str(ROOT / 'runner')),
            ('wrapper', '/etc/systemd/system/provenance-runner.service'),
            ('updater', '/etc/systemd/system/provenance-runner-updater.service')):
        require(p[name]['path'] == expected, 'fixed hosted path')
    boot = b.load_plan(p['bootPlan']['path'], p['bootPlan']['sha256'], require_selection=False)
    require(boot['version'] == 2, 'environment-bound boot plan required')
    for name in ('environmentBefore', 'environmentAfter', 'hookBefore'):
        s = Path(p[name]['path']).stat()
        require(stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and s.st_size <= 512 * 1024,
                'private snapshot custody/bound')
        require(p[name]['path'] not in (boot['runtimeEnvironment'], str(ROOT / 'verify-rootfs')),
                'snapshot overlaps live target')
    before = Path(p['environmentBefore']['path']).read_bytes()
    after = Path(p['environmentAfter']['path']).read_bytes()
    require(b.render_environment(boot, before) == after, 'unrelated environment change')
    legacy = p['legacyRootfs']
    require(isinstance(legacy, dict) and set(legacy) == {'path', 'treeSha256'} and
            legacy['path'] == str(ROOT / 'rootfs') and
            re.fullmatch('[a-f0-9]{64}', legacy['treeSha256']), 'legacy rollback pin')
    previous, _ = b.environment(before, b.runtime_values(boot))
    require(previous.get('PROVENANCE_ROOTFS') == legacy['path'] and
            previous.get('PROVENANCE_ROOTFS_IDENTITY') == 'sha256:' + legacy['treeSha256'] and
            previous.get('PROVENANCE_RUNSC_PATH') == str(ROOT / 'runsc-rootless') and
            previous.get('PROVENANCE_GVISOR_CGROUP_DRIVER') == 'systemd-user' and
            not any(k in previous for k in ('PROVENANCE_MEASURED_RUNTIME_MODE',
                    'PROVENANCE_MEASURED_ROOTFS_IMAGE', 'PROVENANCE_MEASURED_LOOP_DEVICE')),
            'expected legacy environment required')
    return p, boot


def drain(path, sha, plan_sha):
    d = g.read_json(path, sha)
    require(set(d) == {'version', 'planSha256', 'issuedAt', 'expiresAt',
                       'platformDrainEvidenceSha256', 'activeLeases', 'pendingTerminalReplay'},
            'drain fields')
    require(type(d['version']) is int and d['version'] == 1 and d['planSha256'] == plan_sha and
            type(d['issuedAt']) is int and type(d['expiresAt']) is int and
            d['issuedAt'] <= time.time() < d['expiresAt'] <= d['issuedAt'] + 300 and
            isinstance(d['platformDrainEvidenceSha256'], str) and
            re.fullmatch('[a-f0-9]{64}', d['platformDrainEvidenceSha256']) and
            type(d['activeLeases']) is int and d['activeLeases'] == 0 and
            type(d['pendingTerminalReplay']) is int and d['pendingTerminalReplay'] == 0,
            'fresh complete coordinator drain required')


def quiet(p, boot):
    b.loaded_unit(boot, 'mountUnit', lambda *args: b.run('systemctl', *args))
    for name in ('wrapper', 'updater'):
        b.loaded_unit(p, name, lambda *args: b.run('systemctl', *args))
        unit = Path(p[name]['path']).name
        require(b.run('systemctl', 'show', unit, '--property=ActiveState', '--value')
                in ('inactive', 'failed'), 'root service must be stopped')
    b.quiet(boot)
    for name in ('operation.json', 'catalog-operation.json'):
        path = ROOT / 'update-state' / name
        if path.exists() or path.is_symlink():
            operation = g.read_json(path)
            require(isinstance(operation, dict) and operation.get('phase') == 'complete',
                    'updater operation incomplete')
    journal = Path('/var/lib/provenance-runner/config/.provenance-runner-journal.json')
    require(journal.resolve() == journal, 'journal path')
    # Worker-owned data is untrusted: only a bounded read, never executable input.
    for parent in journal.parents:
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, boot['uid']) and
                not s.st_mode & 0o022, 'journal ancestry')
    fd = os.open(journal, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid == boot['uid'] and
                s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size <= 256 * 1024,
                'journal custody/bound')
        data = f.read(256 * 1024 + 1)
        require(len(data) <= 256 * 1024, 'journal grew beyond bound')
        def unique(items):
            result = {}
            for key, value in items:
                require(key not in result, 'duplicate journal member')
                result[key] = value
            return result
        value = json.loads(data, object_pairs_hook=unique)
    require(isinstance(value, dict) and value.get('schemaVersion') == 'provenance.runner-journal/v1alpha1' and
            value.get('active') is None and value.get('credentialRotation') is None and
            value.get('pendingMessage') in (None, ''),
            'local replay not quiet')


def state(p, boot):
    env = g.protected(boot['runtimeEnvironment'])
    s = env.stat()
    require(s.st_gid == boot['gid'] and stat.S_IMODE(s.st_mode) == 0o640 and s.st_nlink == 1,
            'live environment custody')
    target = g.protected(ROOT / 'verify-rootfs')
    s = target.stat()
    require(s.st_gid == 0 and stat.S_IMODE(s.st_mode) == 0o755 and s.st_nlink == 1,
            'live hook custody')
    hashes = (g.fingerprint(env)['sha256'], g.fingerprint(target)['sha256'])
    old_env, new_env = p['environmentBefore']['sha256'], p['environmentAfter']['sha256']
    old_hook, new_hook = p['hookBefore']['sha256'], digest(hook(p))
    require(hashes in ((old_env, old_hook), (old_env, new_hook), (new_env, new_hook)),
            'unreviewed selection state')
    return hashes


def transition(p, boot, action, check):
    # New hook first: any interrupted select refuses boot on the still-old env.
    # Old environment first on rollback gives the same fail-closed intermediate.
    old_env = Path(p['environmentBefore']['path']).read_bytes()
    new_env = Path(p['environmentAfter']['path']).read_bytes()
    old_hook = Path(p['hookBefore']['path']).read_bytes()
    items = ((ROOT / 'verify-rootfs', hook(p)), (Path(boot['runtimeEnvironment']), new_env))
    if action == 'rollback':
        items = ((Path(boot['runtimeEnvironment']), old_env), (ROOT / 'verify-rootfs', old_hook))
    check()
    state(p, boot)
    # Exact retained legacy tree is required for either direction. It is not
    # silently reprovisioned, and rollback doesn't claim a weaker tree is valid.
    g.legacy({'legacyRootfs': p['legacyRootfs']})
    for target, data in items:
        check()
        state(p, boot)
        current = g.fingerprint(target)['sha256']
        if current != digest(data):
            g.replace_file(target, current, data)
    check()
    state(p, boot)
    if action == 'select':
        b.selected_environment(boot)
        b.execute(boot, 'ensure')
    # Rollback deliberately retains the inactive generation/mount for diagnosis.
    # It never detaches a device, edits the binary or starts the legacy runner.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('select', 'rollback'))
    for name in ('plan', 'plan-sha256', 'drain', 'drain-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0 and all(re.fullmatch('[a-f0-9]{64}', x)
            for x in (args.plan_sha256, args.drain_sha256)), 'root and digests required')
    # The shared legacy hash primitive invokes tar; do not inherit operator
    # lookup paths, loader settings or TAR_OPTIONS into privileged verification.
    os.environ.clear()
    os.environ.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C')
    p, boot = load(args.plan, args.plan_sha256)
    lock = g.protected(ROOT / 'update-state/lock')
    require(stat.S_IMODE(lock.stat().st_mode) == 0o600 and lock.stat().st_nlink == 1,
            'updater lock custody')
    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    generation = os.open(boot['generation'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(generation, fcntl.LOCK_EX | fcntl.LOCK_NB)
        p, boot = load(args.plan, args.plan_sha256)
        def check():
            drain(args.drain, args.drain_sha256, args.plan_sha256)
            quiet(p, boot)
        transition(p, boot, args.action, check)
    finally:
        os.close(generation)
        os.close(fd)
    print(json.dumps({'action': args.action, 'planSha256': args.plan_sha256,
                      'runnerStarted': False, 'generationRetained': True}))


if __name__ == '__main__':
    try:
        main()
    except (g.Refusal, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('measured runtime selection refused; retain state for operator inspection', file=sys.stderr)
        sys.exit(1)
