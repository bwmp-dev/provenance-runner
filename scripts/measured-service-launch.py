#!/usr/bin/env python3
"""Pinned root-service boot preparation and launch. Never installs or drains."""
import hashlib
import grp
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

spec = importlib.util.spec_from_file_location('storage', Path(__file__).with_name('measured-storage.py'))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)
b, g, require = storage.b, storage.g, storage.require
ROOT = Path('/opt/provenance-runner')
PLAN = Path('/etc/provenance/measured-launch.json')
CGROUP = Path('/sys/fs/cgroup/system.slice/provenance-measured.service')
DATA = Path('/var/lib/provenance-measured/data')
RUN = Path('/run/provenance-measured')
SECRET = RUN / 'secrets'
ROLES = {'provenance-job': 262144, 'provenance-job-overflow': 262145,
         'provenance-router': 262146, 'provenance-router-overflow': 262147}


def unit_bytes(boot, disk, secret):
    names = ' '.join(Path(p['mountUnit']['path']).name for p in (boot, disk, secret))
    return ('[Unit]\nDescription=Provenance measured root controller\nRequires=' + names +
            '\nAfter=' + names + '\n\n[Service]\nType=notify\nNotifyAccess=main\nUser=root\nGroup=root\n'
            'ExecStartPre=/usr/bin/python3 -I /opt/provenance-runner/measured-service-launch.py prepare-boot\n'
            'ExecStart=/usr/bin/python3 -I /opt/provenance-runner/measured-service-launch.py\n'
            'Delegate=cpu memory pids\nDelegateSubgroup=controller\n'
            'CPUQuota=600%\nCPUQuotaPeriodSec=100ms\nMemoryMax=12G\nMemorySwapMax=0\n'
            'TasksMax=2048\nUMask=0077\nLimitNOFILE=4096\n'
            'RuntimeDirectory=provenance-measured/socket\nRuntimeDirectoryMode=0711\n'
            'RuntimeDirectoryPreserve=yes\nTimeoutStartSec=120s\n'
            'KillMode=mixed\nSendSIGKILL=no\nTimeoutStopSec=infinity\n'
            'Restart=on-failure\nRestartSec=5s\n'
            'Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin\n\n'
            '[Install]\nWantedBy=multi-user.target\n').encode()


def secret_unit_bytes():
    return ('[Unit]\nDescription=Provenance bounded volatile test secrets\n\n[Mount]\n'
            'What=tmpfs\nWhere=' + str(SECRET) + '\nType=tmpfs\n'
            'Options=rw,nosuid,nodev,noexec,noswap,size=1M,nr_inodes=256,mode=0711\n'
            'TimeoutSec=60\n').encode()


def private_json(pin):
    info = g.protected(pin['path']).stat()
    require(info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
            'private configuration custody')
    return g.read_json(pin['path'], pin['sha256'])


def numeric(value, maximum):
    require((type(value) is int and value > 0) or
            (isinstance(value, str) and re.fullmatch('[1-9][0-9]{0,19}', value)), 'canonical resource bound')
    require(int(value) <= maximum, 'resource exceeds provisioned envelope')


def job_limits(resources):
    for key, minimum, maximum in (('cpuMillis', 10, 2000), ('memoryBytes', 16 << 20, 4 << 30),
                                 ('diskBytes', 1 << 20, 8 << 30), ('processCount', 1, 512)):
        numeric(resources[key], maximum)
        require(int(resources[key]) >= minimum, 'minimum resource envelope')
    # Exact ControllerResources contract: a maximum workload plus a maximum
    # router, each including the 17-task mapped-runtime reserve. Not loose caps.
    return {'cpu.max': str(2 * int(resources['cpuMillis']) * 100) + ' 100000',
            'cpu.max.burst': '0', 'memory.max': str(2 * int(resources['memoryBytes'])),
            'memory.swap.max': '0', 'pids.max': str(2 * (int(resources['processCount']) + 17)),
            'cgroup.max.descendants': '2', 'cgroup.max.depth': '1', 'memory.oom.group': '1'}


def configuration(p, boot):
    config = private_json(p['config'])
    expected = {'version': 1, 'workerUid': boot['uid'], 'workerGid': boot['gid'],
                'cgroupParent': str(CGROUP / 'jobs'), 'bundleRoot': str(DATA / 'bundles'),
                'cgroupState': str(DATA / 'cgroups'), 'bundleState': str(DATA / 'bundle-journal'),
                'uplinkState': str(DATA / 'uplinks'), 'secretRoot': str(SECRET),
                'socketDirectory': str(RUN / 'socket'), 'sandboxPath': boot['runsc']['path'],
                'rootPath': boot['rootfs'], 'imagePath': boot['image']['path'], 'loopPath': boot['loop'],
                'runnerSha256': p['runner']['sha256'], 'sandboxSha256': boot['runsc']['sha256'],
                'rootfsSha256': boot['image']['sha256']}
    require(all(config.get(k) == v for k, v in expected.items()), 'daemon provisioning binding')
    numeric(config['maximumInputBytes'], 1 << 30)
    policy = config['maximumPolicy']
    require(isinstance(policy, dict) and isinstance(policy.get('resources'), dict), 'maximum resource policy')
    job_limits(policy['resources'])
    return config


def verify_identities(config, inventory_path):
    require(config['workerUid'] == 994 and config['workerGid'] == 981 and
            config['workload'] == {'UID': 262144, 'GID': 262144, 'OverflowUID': 262145, 'OverflowGID': 262145}
            and config['router'] == {'UID': 262146, 'GID': 262146, 'OverflowUID': 262147, 'OverflowGID': 262147},
            'reserved hosted mappings required')
    for name, identity in ROLES.items():
        user, group = pwd.getpwnam(name), grp.getgrnam(name)
        require(user.pw_uid == user.pw_gid == group.gr_gid == identity and group.gr_mem == [] and
                user.pw_shell == '/usr/sbin/nologin' and user.pw_dir == '/nonexistent',
                'locked identity reservation drift')
    selected = set(ROLES.values())
    require(all(user.pw_name in ROLES for user in pwd.getpwall()
                if user.pw_uid in selected or user.pw_gid in selected), 'borrowed account identity')
    require(all(group.gr_name in ROLES for group in grp.getgrall() if group.gr_gid in selected),
            'borrowed group identity')
    spec = importlib.util.spec_from_file_location('inventory', inventory_path)
    inventory = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inventory)
    for path in ('/etc/subuid', '/etc/subgid'):
        require(not inventory.conflicts(selected, inventory.ranges(inventory.bounded(path), True)),
                'subordinate mapping overlap')
    shadow = inventory.bounded(g.protected('/etc/shadow'))
    locked = set()
    for line in shadow.splitlines():
        fields = line.split(':')
        if fields[0] in ROLES:
            require(len(fields) == 9 and fields[0] not in locked and fields[1].startswith(('!', '*')),
                    'reservation password enabled')
            locked.add(fields[0])
    require(locked == set(ROLES), 'missing locked reservation')


def verify_secrets(p):
    pin = p['secretMount']
    require(pin['path'] == '/etc/systemd/system/' +
            b.run('systemd-escape', '--path', '--suffix=mount', str(SECRET)), 'secret mount name')
    require(Path(pin['path']).read_bytes() == secret_unit_bytes(), 'secret mount contents')
    b.loaded_unit({'mountUnit': pin}, 'mountUnit', lambda *args: b.run('systemctl', *args))
    mount = g.mount_info(SECRET)
    require(mount['fstype'] == 'tmpfs' and
            {'rw', 'nosuid', 'nodev', 'noexec', 'noswap'} <= set(mount['options'].split(',')),
            'secret volatile mount options')
    require(b.run('findmnt', '--submounts', '--raw', '--noheadings', '--output', 'TARGET',
                  '--mountpoint', str(SECRET)).splitlines() == [str(SECRET)], 'nested secret mount')
    info = g.protected(SECRET, True).stat()
    require(info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o711, 'secret mount custody')
    usage = os.statvfs(SECRET)
    require(usage.f_blocks * usage.f_frsize == 1 << 20 and usage.f_files == 256,
            'secret memory/inode capacity')


def load_inputs():
    info = g.protected(PLAN).stat()
    require(info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
            'launch plan custody')
    p = g.read_json(PLAN)
    names = {'runner', 'config', 'bootPlan', 'storagePlan', 'unit', 'secretMount',
             'launcher', 'bootHelper', 'generationHelper', 'storageHelper', 'inventoryHelper'}
    require(isinstance(p, dict) and set(p) == names | {'version'} and
            type(p['version']) is int and p['version'] == 1, 'launch plan fields')
    paths = []
    for name in sorted(names):
        pin = p[name]
        require(isinstance(pin, dict) and set(pin) == {'path', 'sha256'} and
                isinstance(pin['sha256'], str) and re.fullmatch('[a-f0-9]{64}', pin['sha256']),
                'launch pin')
        b.safe_path(pin['path'], mount_unit=name == 'secretMount')
        g.fingerprint(pin['path'], pin['sha256'], executable=name == 'runner')
        paths.append(pin['path'])
    require(len(set(paths)) == len(paths) and str(PLAN) not in paths, 'overlapping launch inputs')
    for name, path in {'runner': ROOT / 'runner', 'config': Path('/etc/provenance/measured-service.json'),
                       'unit': Path('/etc/systemd/system/provenance-measured.service'),
                       'launcher': ROOT / 'measured-service-launch.py',
                       'bootHelper': ROOT / 'measured-rootfs-boot.py',
                       'generationHelper': ROOT / 'runtime-generation.py',
                       'inventoryHelper': ROOT / 'measured-host-inventory.py',
                       'storageHelper': ROOT / 'measured-storage.py'}.items():
        require(p[name]['path'] == str(path), 'fixed service path')
    boot = b.load_plan(p['bootPlan']['path'], p['bootPlan']['sha256'])
    require(boot['version'] == 2, 'selected environment-bound image required')
    disk = storage.load(p['storagePlan']['path'], p['storagePlan']['sha256'])
    require(disk['mountpoint'] == str(DATA) and disk['backing']['sizeBytes'] == 8 << 30,
            'dedicated persistent storage binding')
    require(Path(p['unit']['path']).read_bytes() == unit_bytes(boot, disk, {'mountUnit': p['secretMount']}),
            'service unit contents')
    b.loaded_unit(p, 'unit', lambda *args: b.run('systemctl', *args))
    config = configuration(p, boot)
    verify_identities(config, p['inventoryHelper']['path'])
    return p, boot, disk, config


def prepare_boot():
    # Native Requires/After ordering starts this controller before the worker's
    # own ExecStartPre. Repair the private loop alias here, not in that later
    # worker hook. A previously mounted image may receive another loop number
    # after a cold boot; the global loop device is never detached or changed.
    p, boot, disk, _ = load_inputs()
    for key, expected in (('ActiveState', 'activating'), ('SubState', 'start-pre')):
        require(b.run('systemctl', 'show', Path(p['unit']['path']).name,
                      '--property=' + key, '--value') == expected, 'root pre-start phase required')
    for plan in (boot, disk):
        require(b.run('systemctl', 'show', Path(plan['mountUnit']['path']).name,
                      '--property=ActiveState', '--value') == 'active', 'required mount must be ready')
    storage.execute(disk, 'verify')
    verify_secrets(p)
    b.execute(boot, 'ensure')  # Includes stopped-worker/scope checks before repair.


def load():
    p, boot, disk, config = load_inputs()
    storage.execute(disk, 'verify')
    b.execute(boot, 'verify')
    verify_secrets(p)
    return p, config['maximumPolicy']['resources']


def control(path, name, value=None):
    require(g.protected(path, True).stat().st_uid == 0, 'root control group')
    target = g.protected(path / name)
    if value is not None:
        fd = os.open(target, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            require(os.write(fd, value.encode()) == len(value), 'control write')
        finally:
            os.close(fd)
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw = os.read(fd, 4097)
        require(len(raw) <= 4096, 'control read bound')
        return raw.decode('ascii').strip()
    finally:
        os.close(fd)


def prepare_cgroups(resources):
    limits = job_limits(resources)
    require(Path('/proc/self/cgroup').read_text() ==
            '0::/system.slice/provenance-measured.service/controller\n', 'delegated controller placement')
    require(b.run('stat', '-f', '-c', '%T', str(CGROUP)) == 'cgroup2fs', 'unified control filesystem')
    controller = CGROUP / 'controller'
    require(control(CGROUP, 'cgroup.procs') == '' and control(CGROUP, 'cgroup.type') == 'domain' and
            control(controller, 'cgroup.procs') == str(os.getpid()), 'exclusive controller process')
    require(not any(p.is_dir() for p in controller.iterdir()), 'nested controller group')
    for name, expected in (('cpu.max', '600000 100000'), ('memory.max', str(12 << 30)),
                           ('memory.swap.max', '0'), ('pids.max', '2048')):
        require(control(CGROUP, name) == expected, 'systemd aggregate resource envelope')
    require({'cpu', 'memory', 'pids'} <= set(control(CGROUP, 'cgroup.controllers').split()),
            'delegated resource controllers available')
    # systemd delegates availability, not necessarily subtree activation. The
    # service's already empty parent is ours; never modify its ancestors.
    require({'cpu', 'memory', 'pids'} <= set(control(CGROUP, 'cgroup.subtree_control',
            '+cpu +memory +pids').split()), 'delegated resource controllers enabled')
    jobs = CGROUP / 'jobs'
    try:
        jobs.mkdir(mode=0o700)
    except FileExistsError:
        require(stat.S_IMODE(g.protected(jobs, True).stat().st_mode) == 0o700, 'existing jobs group custody')
    else:
        jobs.chmod(0o700)
    require(control(jobs, 'cgroup.procs') == '' and control(jobs, 'cgroup.type') == 'domain',
            'empty aggregate job parent')
    require({'cpu', 'memory', 'pids'} <= set(control(jobs, 'cgroup.controllers').split()),
            'job controllers available')
    if any(p.is_dir() for p in jobs.iterdir()):
        # Crash recovery belongs to the daemon's retained journals. Do not
        # silently change an outstanding job's aggregate envelope beforehand.
        require(all(control(jobs, name) == value for name, value in limits.items()),
                'occupied job parent resource drift')
    for group, group_limits in ((controller, {'memory.max': str(512 << 20), 'memory.swap.max': '0',
                                      'pids.max': '256', 'cpu.max': '100000 100000'}),
                          (jobs, limits)):
        for name, value in group_limits.items():
            require(control(group, name, value) == value, 'child resource envelope')
    enabled = control(jobs, 'cgroup.subtree_control', '+cpu +memory +pids')
    require({'cpu', 'memory', 'pids'} <= set(enabled.split()), 'job delegation')


def main():
    require(sys.argv[1:] in ([], ['prepare-boot']) and os.getuid() == os.geteuid() == 0,
            'closed root entrypoint')
    if sys.argv[1:] == ['prepare-boot']:
        os.environ.clear()
        os.environ.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C')
        os.setgroups([])
        prepare_boot()
        return
    notify = os.environ.get('NOTIFY_SOCKET')
    require(notify == '/run/systemd/notify', 'root systemd readiness socket required')
    os.environ.clear()
    os.environ.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C')
    os.environ['NOTIFY_SOCKET'] = notify
    os.setgroups([])
    p, resources = load()
    prepare_cgroups(resources)
    # Retain the measured executable through exec; a concurrent path replacement
    # cannot change the launched object after the final digest check.
    fd = os.open(p['runner']['path'], os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb', closefd=False) as source:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o6022 and
                info.st_size <= 512 << 20 and hashlib.file_digest(source, 'sha256').hexdigest() ==
                p['runner']['sha256'], 'retained executable identity')
    os.execve(fd, [p['runner']['path'], 'measured-service', p['config']['path']], dict(os.environ))


if __name__ == '__main__':
    try:
        main()
    except (g.Refusal, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('measured service launch refused; preserve provisioning and journals', file=sys.stderr)
        sys.exit(1)
