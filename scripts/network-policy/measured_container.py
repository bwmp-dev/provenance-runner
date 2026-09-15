#!/usr/bin/env python3
"""Actual image/loop fixture in a new privileged network-none container only."""
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15).stdout.strip()


def main():
    assert os.getuid() == 0 and Path('/.dockerenv').is_file()
    assert sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo']
    assert Path('/proc/self/cgroup').read_text() == '0::/\n'
    cgroup = Path('/sys/fs/cgroup')
    controller = cgroup/'provenance-fixture-controller'
    jobs = cgroup/'provenance-fixture-jobs'
    assert not controller.exists() and not jobs.exists()
    controller.mkdir(mode=0o700)
    (controller/'cgroup.procs').write_text(str(os.getpid()))
    assert (cgroup/'cgroup.procs').read_text() == ''
    (cgroup/'cgroup.subtree_control').write_text('+cpu +memory +pids')
    jobs.mkdir(mode=0o700)
    (jobs/'cgroup.subtree_control').write_text('+cpu +memory +pids')
    state = Path('/state-input/journal')
    assert not state.exists()
    state.mkdir(mode=0o700)
    bundle_state = Path('/state-input/bundle-journal')
    bundle_state.mkdir(mode=0o700)
    bundle_source = Path('/state-input/bundles')
    bundle_source.mkdir(mode=0o711)
    bundles = Path('/tmp/bundle-input')
    bundles.mkdir(mode=0o711)
    run('mount', '--bind', str(bundle_source), str(bundles))
    assert len(sys.argv) == 3
    root = Path('/tmp/provenance-runtime-fixture')
    assert not root.exists()
    root.mkdir(mode=0o755)
    (root/'mount').mkdir(mode=0o755)
    (root/'work').mkdir(mode=0o711)
    for source, target, mode in ((sys.argv[1], '/tmp/measured-route.test', 0o555),
                                  (sys.argv[2], str(root/'image.squashfs'), 0o444),
                                  ('/opt/gvisor/runsc', str(root/'runsc'), 0o555)):
        shutil.copyfile(source, target)
        os.chmod(target, mode)
    loop = None
    mounted = False
    try:
        # Allocation is host-global: ask the kernel for a free device, and never
        # detach an existing mapping. Device nodes are container-private.
        allocation_error = ''
        for _ in range(8):
            free = run('losetup', '-f')
            assert re.fullmatch(r'/dev/loop[0-9]+', free)
            if not Path(free).exists():
                os.mknod(free, stat.S_IFBLK | 0o444, os.makedev(7, int(free[9:])))
            try:
                # LOOP_SET_FD refuses an already associated device if another
                # allocator won this free-device race; retry, never detach it.
                run('losetup', '-r', free, str(root/'image.squashfs'))
                loop = free
                break
            except subprocess.CalledProcessError as error:
                allocation_error = error.stderr[-1024:]
                continue
        assert loop and re.fullmatch(r'/dev/loop[0-9]+', loop), allocation_error
        backing = Path('/sys/block')/Path(loop).name/'loop/backing_file'
        assert backing.read_text().strip() == str(root/'image.squashfs')
        os.chmod(loop, 0o444)
        run('mount', '-t', 'squashfs', '-o', 'ro,nosuid,nodev', loop, str(root/'mount'))
        mounted = True
        result = subprocess.run(['/tmp/measured-route.test', '-test.v',
                                 '-test.run=^Test(MeasuredAuthorityRouteSentry(Withdrawal|Expiry|ChildMismatch|OwnedLaunch|OwnedNormal|OwnedGatedStartup|JournalRefusal|BundleRefusal|PreparedRefusal)|MeasuredBundleJournalKernelRecovery)$',
                                 '-test.count=3', '-test.timeout=200s'],
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                     'PROVENANCE_DISPOSABLE_NETWORK_FIXTURE': '1',
                                     'PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE': '1'},
                                capture_output=True, text=True, timeout=210)
        assert len(result.stdout) <= 65536 and len(result.stderr) <= 65536
        print(result.stdout, end='')
        if result.returncode:
            raise RuntimeError('measured routed fixture failed: '+result.stderr[-4096:])
        assert '--- SKIP:' not in result.stdout
        for case in ('Withdrawal', 'Expiry', 'ChildMismatch', 'OwnedLaunch', 'OwnedNormal', 'OwnedGatedStartup', 'JournalRefusal', 'BundleRefusal', 'PreparedRefusal'):
            assert result.stdout.count('--- PASS: TestMeasuredAuthorityRouteSentry'+case+' ') == 3
        assert result.stdout.count('--- PASS: TestMeasuredBundleJournalKernelRecovery ') == 3
        assert not [p for p in jobs.iterdir() if p.is_dir()]
        jobs.rmdir()
        assert [p.name for p in state.iterdir()] == ['.lock']
        (state/'.lock').unlink()
        state.rmdir()
        assert not list(bundles.iterdir())
        assert [p.name for p in bundle_state.iterdir()] == ['.lock']
        (bundle_state/'.lock').unlink()
        bundle_state.rmdir()
        print('{"measuredBundleJournalRetired": true}')
        print('{"measuredJobJournalRetired": true}')
        print('{"exclusiveMeasuredJobScopesRemoved": true}')
    finally:
        if mounted:
            run('umount', str(root/'mount'))
        if loop:
            assert backing.read_text().strip() == str(root/'image.squashfs')
            run('losetup', '-d', loop)
            assert not backing.exists(), 'owned image loop remains associated'
            print('{"measuredRoutedOwnedLoopDetached": true}')
        run('umount', str(bundles))


if __name__ == '__main__':
    main()
