#!/usr/bin/env python3
"""Exclusive job cgroup lifecycle in a fresh private-cgroup, network-none container."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid


def validate_report(stdout, stderr, status):
    assert len(stdout) <= 65536 and len(stderr) <= 65536
    assert status == 0, stderr[-4096:]
    assert stdout.count('--- PASS: TestJobCgroupKernelLifecycle ') == 3
    assert stdout.count('--- PASS: TestJobCgroupKernelLifecycle/pre-cleanup-pid-denial ') == 3
    assert stdout.count('--- PASS: TestJobCgroupJournalKernelRecovery ') == 3
    assert '--- SKIP:' not in stdout and '--- FAIL:' not in stdout


def inside():
    assert os.geteuid() == 0 and Path('/.dockerenv').is_file()
    assert Path('/proc/self/cgroup').read_text() == '0::/\n'
    assert sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo']
    root = Path('/sys/fs/cgroup')
    controller = root/'provenance-fixture-controller'
    jobs = root/'provenance-fixture-jobs'
    assert not controller.exists() and not jobs.exists()
    # Only the fresh container namespace root is touched. Move this fixture
    # process before enabling its children; never move any host/other process.
    controller.mkdir(mode=0o700)
    (controller/'cgroup.procs').write_text(str(os.getpid()))
    assert (root/'cgroup.procs').read_text() == ''
    (root/'cgroup.subtree_control').write_text('+cpu +memory +pids')
    jobs.mkdir(mode=0o700)
    (jobs/'cgroup.subtree_control').write_text('+cpu +memory +pids')
    state = Path('/state-input/journal')
    assert not state.exists()
    state.mkdir(mode=0o700)
    result = subprocess.run(['/test-input', '-test.v', '-test.run=^TestJobCgroup(KernelLifecycle|JournalKernelRecovery)$',
                             '-test.count=3', '-test.timeout=30s'], cwd='/repo/internal/networkpolicy',
                            env={'PATH': '/usr/bin:/bin', 'PROVENANCE_DISPOSABLE_JOB_CGROUP_FIXTURE': '1'},
                            capture_output=True, text=True, timeout=40)
    print(result.stdout, end='')
    validate_report(result.stdout, result.stderr, result.returncode)
    assert [p.name for p in state.iterdir()] == ['.lock']
    (state/'.lock').unlink()
    state.rmdir()
    assert not [p for p in jobs.iterdir() if p.is_dir()]
    jobs.rmdir()
    print(json.dumps({'ownedJobCgroupRemoved': True, 'descendantCleanup': True,
                      'preCleanupPIDDenialObserved': True,
                      'journalCrashRecoveryAndLock': True,
                      'staleLaunchFDRefused': True, 'controllerSurvived': True, 'repetitions': 3}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--image')
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    if args.inside:
        inside()
        return
    assert args.image and re.fullmatch(r'sha256:[0-9a-f]{64}', args.image)
    repo = Path(__file__).resolve().parents[2]
    # A real persistent local filesystem is required by the journal; do not
    # inherit RAM-only TMPDIR or /tmp (tmpfs on current Ubuntu CI hosts).
    with tempfile.TemporaryDirectory(prefix='provenance-job-cgroup-', dir='/var/tmp', ignore_cleanup_errors=True) as directory:
        binary = Path(directory)/'cgroup.test'
        subprocess.run([args.go, 'test', '-c', '-o', str(binary), './internal/networkpolicy'],
                       cwd=repo, env=os.environ | {'CGO_ENABLED': '0'}, check=True, timeout=180)
        name = 'provenance-job-cgroup-'+uuid.uuid4().hex
        subprocess.run(['docker', 'create', '--name', name, '--privileged', '--cgroupns', 'private',
                        '--network', 'none', '--read-only', '--memory', '512m', '--memory-swap', '512m',
                        '--cpus', '2', '--pids-limit', '128', '--tmpfs', '/tmp:rw,nosuid,size=16m',
                        '--mount', f'type=bind,src={repo},dst=/repo,readonly',
                        '--mount', f'type=bind,src={binary},dst=/test-input,readonly',
                        '--mount', f'type=bind,src={directory},dst=/state-input',
                        '--entrypoint', 'python3', args.image,
                        '/repo/scripts/network-policy/job_cgroup_acceptance.py', '--inside'],
                       check=True, capture_output=True, timeout=30)
        try:
            result = subprocess.run(['docker', 'start', '--attach', name], capture_output=True, text=True, timeout=60)
            assert len(result.stdout) <= 65536 and len(result.stderr) <= 65536
            print(result.stdout, end='')
            assert result.returncode == 0, result.stderr[-4096:]
            assert subprocess.check_output(['docker', 'inspect', '--format', '{{.State.ExitCode}}', name], text=True).strip() == '0'
            validate_report(result.stdout, result.stderr, result.returncode)
            assert '"ownedJobCgroupRemoved": true' in result.stdout
            print(json.dumps({'fixtureImage': args.image,
                              'testBinarySHA256': hashlib.sha256(binary.read_bytes()).hexdigest()}))
        finally:
            subprocess.run(['docker', 'wait', name], check=True, capture_output=True, timeout=60)
            subprocess.run(['docker', 'rm', name], check=True, capture_output=True, timeout=15)


if __name__ == '__main__':
    main()
