#!/usr/bin/env python3
"""Disposable wrapper cold-start proof; never a host reboot or signed update."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location('boot', '/opt/measured-rootfs-boot.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def write(path, data, mode=0o644):
    with path.open('xb') as output:
        output.write(data)
    path.chmod(mode)


def load():
    path = Path('/opt/boot-fixture/plan.json')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return b.load_plan(str(path), digest), path, digest


def main():
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    p, plan, digest = load()
    wrapper = Path('/etc/systemd/system/provenance-boot-fixture.service')
    unit = Path(p['mountUnit']['path'])
    if sys.argv[1] == 'prepare':
        assert Path('/run/provenance-boot-disposable').read_text() == 'measured-boot-disposable-only\n'
        assert not os.path.ismount(p['rootfs'])
        env = ('/usr/sbin/runuser -u boot-fixture -- /usr/bin/env '
               'XDG_RUNTIME_DIR=/run/user/1994 '
               'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1994/bus '
               '/usr/bin/systemctl --user ')
        data = ('[Unit]\nRequires=user@1994.service\nAfter=user@1994.service\n'
                '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                'ExecStartPre=/usr/bin/python3 -B /opt/measured-rootfs-boot.py ensure '
                '--plan=' + str(plan) + ' --plan-sha256=' + digest + '\n'
                'ExecStart=' + env + 'start provenance-runner.service\n'
                'ExecStop=' + env + 'stop provenance-runner.service\n'
                'TimeoutStartSec=120\nTimeoutStopSec=30\n'
                '[Install]\nWantedBy=multi-user.target\n')
        write(wrapper, data.encode())
        b.run('systemctl', 'daemon-reload')
        b.run('systemctl', 'enable', wrapper.name)
        assert b.userctl(p, 'is-enabled', 'provenance-runner.service') == 'static'
        write(Path('/opt/boot-fixture/wrapper-proof.json'), json.dumps({
            'wrapperSha256': hashlib.sha256(wrapper.read_bytes()).hexdigest(),
            'pid1Start': Path('/proc/1/stat').read_text().split()[21]}).encode(), 0o600)
        print(json.dumps({'wrapperPreparedButNotStarted': True}))
    elif sys.argv[1] == 'verify-cleanup':
        record = json.loads(Path('/opt/boot-fixture/wrapper-proof.json').read_text())
        assert not Path('/run/provenance-boot-disposable').exists()
        assert Path('/proc/1/stat').read_text().split()[21] != record['pid1Start']
        assert hashlib.sha256(wrapper.read_bytes()).hexdigest() == record['wrapperSha256']
        assert b.run('systemctl', 'show', wrapper.name, '--property=ActiveState', '--value') == 'active'
        assert b.run('systemctl', 'show', wrapper.name, '--property=Result', '--value') == 'success'
        assert b.userctl(p, 'show', 'provenance-runner.service', '--property=ActiveState', '--value') == 'active'
        b.execute(p, 'verify')
        try:
            print(json.dumps({'freshSystemdBoot': True, 'wrapperEnsureBeforeUserStart': True,
                              'kernelHostRebootTested': False, 'signedUpdaterTested': False}))
        finally:
            b.run('systemctl', 'stop', wrapper.name)
            b.quiet(p)
            b.mounted(p)
            b.run('systemctl', 'stop', unit.name)
            assert not os.path.ismount(p['rootfs'])
            assert b.run('losetup', '--associated', p['image']['path']) == ''
            b.run('systemctl', 'disable', wrapper.name)
            print(json.dumps({'coldBootOwnedMountAndLoopsAbsent': True}))
    else:
        raise ValueError('unknown fixture action')


if __name__ == '__main__':
    main()
