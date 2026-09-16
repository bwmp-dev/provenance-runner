#!/usr/bin/env python3
"""Systemd delegated cgroup/secret mount proof, not a complete daemon launch."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys

spec = importlib.util.spec_from_file_location('launch', '/opt/measured-service-launch.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
b = s.b
PROOF = Path('/opt/measured-service-launch-proof.json')
RESOURCES = {'cpuMillis': 1000, 'memoryBytes': 128 << 20, 'diskBytes': 256 << 20, 'processCount': 64}


def write(path, data):
    with path.open('xb') as file:
        file.write(data)
    path.chmod(0o644)


def pin(path):
    return {'path': str(path), 'sha256': s.hashlib.sha256(path.read_bytes()).hexdigest()}


def child():
    s.prepare_cgroups(RESOURCES)
    unit = Path('/etc/systemd/system') / b.run('systemd-escape', '--path', '--suffix=mount', str(s.SECRET))
    s.verify_secrets({'secretMount': pin(unit)})
    jobs = s.CGROUP / 'jobs'
    # A leaf receives its own controls; controller stays a sibling, never
    # inside the aggregate parent used for job admission.
    leaf = jobs / 'fixture-leaf'
    leaf.mkdir(mode=0o700)
    try:
        for name, value in (('memory.max', str(64 << 20)), ('memory.swap.max', '0'),
                            ('pids.max', '16'), ('cpu.max', '100000 100000')):
            assert s.control(leaf, name, value) == value
        def attach():
            (leaf / 'cgroup.procs').write_text(str(os.getpid()))
        process = subprocess.Popen(('/usr/bin/sleep', '0.1'), preexec_fn=attach)
        assert process.wait(timeout=5) == 0 and s.control(leaf, 'cgroup.procs') == ''
        expected = s.job_limits(RESOURCES)['pids.max']
        changed = str(int(expected) + 1)
        s.control(jobs, 'pids.max', changed)
        try:
            try:
                s.prepare_cgroups(RESOURCES)
            except s.g.Refusal:
                pass
            else:
                raise AssertionError('occupied aggregate drift accepted')
            assert s.control(jobs, 'pids.max') == changed
        finally:
            s.control(jobs, 'pids.max', expected)
        s.prepare_cgroups(RESOURCES)
    finally:
        leaf.rmdir()
    s.prepare_cgroups(RESOURCES)  # Existing empty aggregate parent is safe to reuse.
    s.control(s.CGROUP, 'memory.max', str(1 << 30))
    try:
        try:
            s.prepare_cgroups(RESOURCES)
        except s.g.Refusal:
            pass
        else:
            raise AssertionError('aggregate drift accepted')
    finally:
        s.control(s.CGROUP, 'memory.max', str(12 << 30))
    s.prepare_cgroups(RESOURCES)
    PROOF.write_text(json.dumps({'actualDelegatedControllerSubgroup': True,
        'emptySiblingJobParent': True, 'jobLeafResourceControls': True,
        'aggregateDriftRefused': True, 'occupiedJobParentDriftRefused': True,
        'boundedNoswapSecretTmpfs': True,
        'fullDaemonComposition': False}))
    def stop(_signal, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        assert os.environ['NOTIFY_SOCKET'] == '/run/systemd/notify'
        notify.sendto(b'READY=1', '/run/systemd/notify')
    finally:
        notify.close()
    try:
        while True:
            signal.pause()
    finally:
        assert s.control(jobs, 'cgroup.procs') == '' and not any(p.is_dir() for p in jobs.iterdir())
        jobs.rmdir()


def main():
    assert os.geteuid() == 0 and Path('/.dockerenv').is_file()
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    if len(sys.argv) == 2 and sys.argv[1] == 'child':
        child()
        return
    units = []
    for target in (Path('/opt/launch-image-fixture'), Path('/opt/launch-storage-fixture'), s.SECRET):
        path = Path('/etc/systemd/system') / b.run('systemd-escape', '--path', '--suffix=mount', str(target))
        body = s.secret_unit_bytes() if target == s.SECRET else (
            '[Mount]\nWhat=tmpfs\nWhere=' + str(target) + '\nType=tmpfs\nOptions=size=1M\n').encode()
        write(path, body)
        units.append({'mountUnit': pin(path), 'mountpoint': str(target)})
    service = Path('/etc/systemd/system/provenance-measured.service')
    unit = s.unit_bytes(*units).replace(
        b'ExecStart=/usr/bin/python3 -I /opt/provenance-runner/measured-service-launch.py\n',
        b'ExecStart=/usr/bin/python3 -I /opt/test-measured-service-launch-fixture.py child\n')
    write(service, unit)
    try:
        b.run('systemctl', 'daemon-reload')
        b.run('systemctl', 'start', service.name)
        assert b.run('systemctl', 'show', service.name, '--property=ActiveState', '--value') == 'active'
        proof = json.loads(PROOF.read_text())
        assert all(value for name, value in proof.items() if name != 'fullDaemonComposition')
        print(json.dumps(proof))
    except Exception:
        # Synthetic guest only: retain bounded unit diagnostics before /run's
        # volatile journal disappears during driver cleanup.
        for name in [service.name, *(Path(p['mountUnit']['path']).name for p in units)]:
            print(b.run('journalctl', '-b', '-u', name, '--no-pager', '-n', '30', '-o', 'cat')[-4096:])
        raise
    finally:
        b.run('systemctl', 'stop', service.name)
        assert not s.CGROUP.exists()
        for unit in reversed(units):
            b.run('systemctl', 'stop', Path(unit['mountUnit']['path']).name)
            assert not os.path.ismount(unit['mountpoint'])
        print(json.dumps({'rootLaunchFixtureOwnedGroupsAndMountsAbsent': True}))


if __name__ == '__main__':
    main()
