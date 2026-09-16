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


def real_paper(jobs, state, bundle_state, bundles):
    result = subprocess.run(['/tmp/measured-service.test', '-test.v',
                             '-test.run=^TestMeasuredPaperRealKernel$', '-test.count=3', '-test.timeout=900s'],
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                 'PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE': '1',
                                 'PROVENANCE_DISPOSABLE_REAL_PAPER_FIXTURE': '1'},
                            capture_output=True, text=True, timeout=910)
    assert len(result.stdout) <= 65536 and len(result.stderr) <= 65536
    print(result.stdout, end='', flush=True)
    assert result.returncode == 0, result.stderr[-4096:]
    assert '--- FAIL:' not in result.stdout and '--- SKIP:' not in result.stdout
    for suffix in ('', '/root-config-permissions', '/root-config-pin-refusal', '/root-idle-barrier-after-retirement'):
        assert result.stdout.count('--- PASS: TestMeasuredPaperRealKernel'+suffix+' ') == 3
    journals = list(Path('/state-input').glob('service-journals-*'))
    assert len(journals) == 3
    for parent in journals:
        assert sorted(p.name for p in parent.iterdir()) == ['bundles', 'cgroups', 'uplinks']
        for journal in parent.iterdir():
            assert [p.name for p in journal.iterdir()] == ['.lock']
    assert not [p for p in jobs.iterdir() if p.is_dir()]
    assert not list(state.iterdir()) and not list(bundle_state.iterdir()) and not list(bundles.iterdir())
    jobs.rmdir()
    state.rmdir()
    bundle_state.rmdir()
    print('{"measuredRealPaperCompatibility": true}')
    print('{"measuredHostUplinkJournalRetired": true}')
    print('{"measuredBundleJournalRetired": true}')
    print('{"measuredJobJournalRetired": true}')
    print('{"exclusiveMeasuredJobScopesRemoved": true}')


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
                                  ('/state-input/service.test', '/tmp/measured-service.test', 0o555),
                                  ('/state-input/download.test', '/tmp/measured-worker.test', 0o555),
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
        if os.environ.get('PROVENANCE_DISPOSABLE_REAL_PAPER_FIXTURE') == '1':
            real_paper(jobs, state, bundle_state, bundles)
            return
        # Exercise the new composed service before the longer regression suite
        # so provisioning failures surface promptly. Both remain mandatory.
        if os.environ.get('PROVENANCE_DISPOSABLE_WORKER_STRESS') == '1':
            stress = subprocess.run(['/tmp/measured-service.test', '-test.v',
                                     '-test.run=^TestMeasuredPaperWorkerKernel$',
                                     '-test.count=20', '-test.timeout=220s'],
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                         'PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE': '1'},
                                    capture_output=True, text=True, timeout=230)
            assert len(stress.stdout) <= 65536 and len(stress.stderr) <= 65536
            if stress.returncode:
                print(stress.stdout, end='', flush=True)
                raise RuntimeError('worker stress failed: '+stress.stderr[-4096:])
            assert '--- SKIP:' not in stress.stdout
            assert stress.stdout.count('--- PASS: TestMeasuredPaperWorkerKernel ') == 20
            print('{"measuredWorkerStressRepetitions": 20}', flush=True)
        service = subprocess.run(['/tmp/measured-service.test', '-test.v',
                                  '-test.run=^TestMeasuredPaper(Service(Withdrawal|ReleaseRefusal|EventRefusal)?|Daemon|Worker)Kernel$',
                                  '-test.count=3', '-test.timeout=120s'],
                                 env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                      'PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE': '1'},
                                 capture_output=True, text=True, timeout=130)
        assert len(service.stdout) <= 65536 and len(service.stderr) <= 65536
        print(service.stdout, end='', flush=True)
        if service.returncode:
            raise RuntimeError('measured root service fixture failed: '+service.stderr[-4096:])
        assert '--- SKIP:' not in service.stdout
        assert service.stdout.count('--- PASS: TestMeasuredPaperServiceKernel ') == 3
        assert service.stdout.count('--- PASS: TestMeasuredPaperServiceWithdrawalKernel ') == 3
        assert service.stdout.count('--- PASS: TestMeasuredPaperServiceReleaseRefusalKernel ') == 3
        assert service.stdout.count('--- PASS: TestMeasuredPaperServiceEventRefusalKernel ') == 3
        assert service.stdout.count('--- PASS: TestMeasuredPaperWorkerKernel ') == 3
        assert service.stdout.count('--- PASS: TestMeasuredPaperWorkerKernel/root-idle-barrier-after-retirement ') == 3
        for suffix in ('', '/root-config-permissions', '/root-config-pin-refusal', '/root-idle-barrier-after-retirement'):
            assert service.stdout.count('--- PASS: TestMeasuredPaperDaemonKernel'+suffix+' ') == 3
        for case in ('', 'Withdrawal', 'ReleaseRefusal', 'EventRefusal'):
            assert service.stdout.count('--- PASS: TestMeasuredPaperService'+case+'Kernel/root-idle-barrier-after-retirement ') == 3
            assert service.stdout.count('--- PASS: TestMeasuredPaperService'+case+'Kernel/root-idle-response-refusal ') == 3
        result = subprocess.run(['/tmp/measured-route.test', '-test.v',
                                 '-test.run=^Test(MeasuredAuthorityRouteSentry(Withdrawal|Expiry|ChildMismatch|OwnedLaunch|OwnedNormal|OwnedGatedStartup|JournalRefusal|BundleRefusal|PreparedRefusal|LinkRefusal|LayoutRefusal|UplinkRefusal)|MeasuredBundleJournalKernelRecovery|MeasuredHostUplinkColdRecovery|MeasuredControlListener|MeasuredNetworkSession(Normal|RouterLoss|StartupRefusal|DNSLoss|DNSRefreshFailure|PreparationTimeout|ExecutionTimeout|ControllerResourceLoss|PaperGuest|PaperGuestRefusal))$',
                                 '-test.count=3', '-test.timeout=410s'],
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                     'PROVENANCE_DISPOSABLE_NETWORK_FIXTURE': '1',
                                     'PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE': '1'},
                                capture_output=True, text=True, timeout=420)
        assert len(result.stdout) + len(service.stdout) <= 131072 and len(result.stderr) <= 65536
        print(result.stdout, end='')
        if result.returncode:
            raise RuntimeError('measured routed fixture failed: '+result.stderr[-4096:])
        assert '--- SKIP:' not in result.stdout
        for case in ('Withdrawal', 'Expiry', 'ChildMismatch', 'OwnedLaunch', 'OwnedNormal', 'OwnedGatedStartup', 'JournalRefusal', 'BundleRefusal', 'PreparedRefusal', 'LinkRefusal', 'LayoutRefusal', 'UplinkRefusal'):
            assert result.stdout.count('--- PASS: TestMeasuredAuthorityRouteSentry'+case+' ') == 3
        assert result.stdout.count('--- PASS: TestMeasuredBundleJournalKernelRecovery ') == 3
        for case in ('success', 'expired', 'cancelled', 'bad-name', 'duplicate', 'oversize', 'persistent'):
            assert result.stdout.count('--- PASS: TestMeasuredBundleJournalKernelRecovery/sealed-secret-tmpfs-materialization/'+case+' ') == 3
        for case in ('normal', 'cold', 'foreign', 'intent-only', 'replaced', 'wrong-boot', 'wrong-parent'):
            assert result.stdout.count('--- PASS: TestMeasuredBundleJournalKernelRecovery/secret-journal-recovery/'+case+' ') == 3
        for case in ('PaperGuest', 'PaperGuestRefusal'):
            assert result.stdout.count('--- PASS: TestMeasuredNetworkSession'+case+'/late-sealed-secret-mount ') == 3
        assert result.stdout.count('--- PASS: TestMeasuredHostUplinkColdRecovery ') == 3
        assert result.stdout.count('--- PASS: TestMeasuredControlListener ') == 3
        assert result.stdout.count('--- PASS: TestMeasuredNetworkSessionRouterLoss/root-observation-transfer ') == 3
        for case in ('TestMeasuredNetworkSessionPaperGuest', 'TestMeasuredNetworkSessionPaperGuestRefusal'):
            assert result.stdout.count(f'--- PASS: {case}/root-result-transfer ') == 3
        for case in ('Normal', 'RouterLoss', 'StartupRefusal', 'DNSLoss', 'DNSRefreshFailure', 'PreparationTimeout', 'ExecutionTimeout', 'ControllerResourceLoss', 'PaperGuest', 'PaperGuestRefusal'):
            assert result.stdout.count('--- PASS: TestMeasuredNetworkSession'+case+' ') == 3
        for case in ('local-maximum-refusal', 'local-identity-refusal'):
            assert result.stdout.count('--- PASS: TestMeasuredNetworkSessionNormal/'+case+' ') == 3
        for case in ('controller-occupied-refusal', 'controller-exclusive-admission', 'controller-staging-failure', 'controller-busy-refusal', 'controller-cleanup-refusal', 'controller-slot-retirement'):
            assert result.stdout.count('--- PASS: TestMeasuredNetworkSessionNormal/'+case+' ') == 3
        uplink_state = Path('/state-input/uplink-journal')
        assert [p.name for p in uplink_state.iterdir()] == ['.lock']
        (uplink_state/'.lock').unlink()
        uplink_state.rmdir()
        print('{"measuredHostUplinkJournalRetired": true}')
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
