#!/usr/bin/env python3
"""Compose measured root execution with native authority enforcement, locally only."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

SOURCE = 'ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517'
BUILDER_SHA = '47d5c1af3da11864e64c9dc6bb4e568719dcc315e6a744e79381ce3374fb7393'


@contextmanager
def fixture_workspace():
    directory = tempfile.mkdtemp(prefix='provenance-measured-route-', dir='/var/tmp')
    try:
        yield directory
    finally:
        # A failed root fixture may leave protected ownership evidence. Preserve
        # that state; do not chmod it or obscure the original acceptance failure.
        shutil.rmtree(directory, ignore_errors=True)


def validate_report(stdout, stderr, status, worker_stress=False):
    # Bounded harness transcript, not guest logs: the expanded repeated secret
    # recovery cases exceed the former 64-KiB report envelope.
    assert len(stdout) <= 131072 and len(stderr) <= 65536
    assert status == 0, stderr[-4096:]
    if worker_stress:
        assert stdout.count('{"measuredWorkerStressRepetitions": 20}') == 1
    assert '{"measuredRoutedOwnedLoopDetached": true}' in stdout
    assert '{"exclusiveMeasuredJobScopesRemoved": true}' in stdout
    assert '{"measuredJobJournalRetired": true}' in stdout
    assert '{"measuredBundleJournalRetired": true}' in stdout
    assert '{"measuredHostUplinkJournalRetired": true}' in stdout
    assert '--- SKIP:' not in stdout and '--- FAIL:' not in stdout
    for case in ('Withdrawal', 'Expiry', 'ChildMismatch', 'OwnedLaunch', 'OwnedNormal', 'OwnedGatedStartup', 'JournalRefusal', 'BundleRefusal', 'PreparedRefusal', 'LinkRefusal', 'LayoutRefusal', 'UplinkRefusal'):
        assert stdout.count('--- PASS: TestMeasuredAuthorityRouteSentry'+case+' ') == 3
    for case in ('success', 'expired', 'cancelled', 'bad-name', 'duplicate', 'oversize', 'persistent'):
        assert stdout.count('--- PASS: TestMeasuredBundleJournalKernelRecovery/sealed-secret-tmpfs-materialization/'+case+' ') == 3
    for case in ('normal', 'cold', 'foreign', 'intent-only', 'replaced', 'wrong-boot', 'wrong-parent'):
        assert stdout.count('--- PASS: TestMeasuredBundleJournalKernelRecovery/secret-journal-recovery/'+case+' ') == 3
    for case in ('PaperGuest', 'PaperGuestRefusal'):
        assert stdout.count('--- PASS: TestMeasuredNetworkSession'+case+'/late-sealed-secret-mount ') == 3
    assert stdout.count('--- PASS: TestMeasuredHostUplinkColdRecovery ') == 3
    assert stdout.count('--- PASS: TestMeasuredControlListener ') == 3
    assert stdout.count('--- PASS: TestMeasuredNetworkSessionRouterLoss/root-observation-transfer ') == 3
    assert stdout.count('--- PASS: TestMeasuredPaperServiceKernel ') == 3
    assert stdout.count('--- PASS: TestMeasuredPaperServiceWithdrawalKernel ') == 3
    assert stdout.count('--- PASS: TestMeasuredPaperServiceReleaseRefusalKernel ') == 3
    assert stdout.count('--- PASS: TestMeasuredPaperServiceEventRefusalKernel ') == 3
    for case in ('Secrets', 'SecretsMissing', 'SecretsExpired'):
        assert stdout.count('--- PASS: TestMeasuredPaperService'+case+'Kernel ') == 3
    assert stdout.count('--- PASS: TestMeasuredPaperWorkerKernel ') == 3
    assert stdout.count('--- PASS: TestMeasuredPaperWorkerSecretsKernel ') == 3
    for case in ('Service', 'ServiceSecrets', 'ServiceSecretsMissing', 'ServiceSecretsExpired', 'ServiceWithdrawal', 'ServiceReleaseRefusal', 'ServiceEventRefusal', 'Daemon', 'Worker', 'WorkerSecrets'):
        assert stdout.count('--- PASS: TestMeasuredPaper'+case+'Kernel/root-secret-capability-after-retirement ') == 3
    for case in ('valid', 'nonce', 'idle', 'short', 'files', 'eof'):
        assert stdout.count('--- PASS: TestMeasuredPaperServiceKernel/root-secret-capability-protocol/'+case+' ') == 3
    assert stdout.count('--- PASS: TestMeasuredPaperWorkerSecretsKernel/root-idle-barrier-after-retirement ') == 3
    assert stdout.count('--- PASS: TestMeasuredPaperWorkerKernel/root-idle-barrier-after-retirement ') == 3
    for suffix in ('', '/root-config-permissions', '/root-config-pin-refusal', '/root-idle-barrier-after-retirement'):
        assert stdout.count('--- PASS: TestMeasuredPaperDaemonKernel'+suffix+' ') == 3
    for case in ('', 'Withdrawal', 'ReleaseRefusal', 'EventRefusal', 'Secrets', 'SecretsMissing', 'SecretsExpired'):
        assert stdout.count('--- PASS: TestMeasuredPaperService'+case+'Kernel/root-idle-barrier-after-retirement ') == 3
        assert stdout.count('--- PASS: TestMeasuredPaperService'+case+'Kernel/root-idle-response-refusal ') == 3
    assert stdout.count('--- PASS: TestMeasuredInputDownloadFixture ') == 3
    for case in ('TestMeasuredNetworkSessionPaperGuest', 'TestMeasuredNetworkSessionPaperGuestRefusal'):
        assert stdout.count(f'--- PASS: {case}/root-result-transfer ') == 3
    for case in ('Normal', 'RouterLoss', 'StartupRefusal', 'DNSLoss', 'DNSRefreshFailure', 'PreparationTimeout', 'ExecutionTimeout', 'ControllerResourceLoss', 'PaperGuest', 'PaperGuestRefusal'):
        assert stdout.count('--- PASS: TestMeasuredNetworkSession'+case+' ') == 3
    for case in ('local-maximum-refusal', 'local-identity-refusal'):
        assert stdout.count('--- PASS: TestMeasuredNetworkSessionNormal/'+case+' ') == 3
    for case in ('controller-occupied-refusal', 'controller-exclusive-admission', 'controller-staging-failure', 'controller-busy-refusal', 'controller-cleanup-refusal', 'controller-slot-retirement'):
        assert stdout.count('--- PASS: TestMeasuredNetworkSessionNormal/'+case+' ') == 3
    for case in ('uplink-alias-refusal', 'uplink-journal-refusal', 'uplink-prefix-refusal'):
        assert stdout.count('--- PASS: TestMeasuredAuthorityRouteSentryOwnedLaunch/'+case+' ') == 3
    for suffix in ('', '/live-scope', '/retired-scope', '/bounded-no-follow-cleanup', '/foreign-directory-and-record-refusal', '/replaced-directory-refusal', '/mount-boundary-refusal'):
        assert stdout.count('--- PASS: TestMeasuredBundleJournalKernelRecovery'+suffix+' ') == 3
    for suffix in ('preparation-failure-is-job-local', 'prepared-drift-configuration', 'prepared-drift-resolver', 'prepared-drift-input', 'prepared-drift-identity', 'prepared-drift-private-root'):
        assert stdout.count('--- PASS: TestMeasuredBundleJournalKernelRecovery/'+suffix+' ') == 3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--builder', required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--worker-stress', action='store_true')
    args = parser.parse_args()
    assert re.fullmatch(r'sha256:[0-9a-f]{64}', args.image)
    builder = Path(args.builder).resolve(strict=True)
    assert hashlib.sha256((builder/'mksquashfs').read_bytes()).hexdigest() == BUILDER_SHA
    repo = Path(__file__).resolve().parents[2]
    with fixture_workspace() as directory:
        work = Path(directory)
        # Both executables are compiled from this exact checkout. They contain
        # synthetic fixtures only and receive no host or platform credentials.
        environment = os.environ | {'CGO_ENABLED': '0'}
        subprocess.run([args.go, 'test', '-c', '-ldflags',
                        '-X github.com/bwmp-dev/provenance-runner/internal/buildinfo.Version=0.1.0-alpha',
                        '-o', str(work/'gvisor.test'), './internal/provider/gvisor'],
                       cwd=repo, env=environment, check=True, timeout=180)
        subprocess.run([args.go, 'test', '-c', '-ldflags',
                        '-X github.com/bwmp-dev/provenance-runner/internal/buildinfo.Version=0.1.0-alpha',
                        '-o', str(work/'service.test'), './internal/measuredservice'],
                       cwd=repo, env=environment, check=True, timeout=180)
        subprocess.run([args.go, 'test', '-c', '-o', str(work/'download.test'),
                        './internal/provider/paper'], cwd=repo, env=environment,
                       check=True, timeout=180)
        subprocess.run([args.go, 'build', '-o', str(work/'guest'), './scripts/network-policy/sentry'],
                       cwd=repo, env=environment, check=True, timeout=180)
        subprocess.run([args.go, 'build', '-o', str(work/'paper-helper'), './cmd/provenance-measured-paper'],
                       cwd=repo, env=environment, check=True, timeout=180)
        build_name = 'provenance-measured-image-'+uuid.uuid4().hex
        runtime_name = 'provenance-measured-route-'+uuid.uuid4().hex
        created = []
        try:
            download_name = 'provenance-measured-download-'+uuid.uuid4().hex
            subprocess.run(['docker', 'create', '--name', download_name,
                            '--network', 'none', '--read-only', '--memory', '512m',
                            '--memory-swap', '512m', '--cpus', '1', '--pids-limit', '64',
                            '--user', '65532:65532', '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m,mode=1777',
                            '--mount', f'type=bind,src={work}/download.test,dst=/download.test,readonly',
                            '--env', 'PROVENANCE_DISPOSABLE_DOWNLOAD_FIXTURE=1',
                            '--entrypoint', '/download.test', args.image, '-test.v',
                            '-test.run=^TestMeasuredInputDownloadFixture$', '-test.count=3',
                            '-test.timeout=60s'], check=True, capture_output=True, timeout=60)
            created.append(download_name)
            download = subprocess.run(['docker', 'start', '--attach', download_name],
                                      capture_output=True, text=True, timeout=75)
            assert len(download.stdout) <= 65536 and len(download.stderr) <= 65536
            assert download.returncode == 0, download.stderr[-4096:]
            assert subprocess.check_output(['docker', 'inspect', '--format', '{{.State.ExitCode}}', download_name], text=True).strip() == '0', download.stdout[-4096:]
            assert download.stdout.count('--- PASS: TestMeasuredInputDownloadFixture ') == 3
            assert '--- SKIP:' not in download.stdout and '--- FAIL:' not in download.stdout
            print(download.stdout, end='', flush=True)
            command = ['docker', 'create', '--name', build_name, '--network', 'none', '--read-only',
                       '--memory', '512m', '--cpus', '1', '--pids-limit', '64',
                       '--tmpfs', '/tmp:rw,exec,nosuid,size=128m',
                       '--mount', f'type=bind,src={repo},dst=/repo,readonly',
                       '--mount', f'type=bind,src={work},dst=/inputs',
                       '--mount', f'type=bind,src={builder},dst=/builder,readonly',
                       SOURCE, 'bash', '/repo/scripts/network-policy/build-measured-fixture.sh',
                       '/inputs/guest', '/builder', '/inputs']
            subprocess.run(command, check=True, capture_output=True, timeout=60)
            created.append(build_name)
            subprocess.run(['docker', 'start', '--attach', build_name], check=True, timeout=60)
            assert subprocess.check_output(['docker', 'inspect', '--format', '{{.State.ExitCode}}', build_name], text=True).strip() == '0'
            command = ['docker', 'create', '--name', runtime_name, '--privileged', '--network', 'none',
                       '--cgroupns', 'private',
                       '--read-only', '--memory', '1g', '--memory-swap', '1g', '--cpus', '2', '--pids-limit', '273',
                       '--tmpfs', '/tmp:rw,exec,nosuid,size=768m',
                       '--mount', f'type=bind,src={repo},dst=/repo,readonly',
                       '--mount', f'type=bind,src={work}/gvisor.test,dst=/test-input,readonly',
                       '--mount', f'type=bind,src={work}/image.squashfs,dst=/image-input,readonly',
                       '--mount', f'type=bind,src={work},dst=/state-input',
                       *(['--env', 'PROVENANCE_DISPOSABLE_WORKER_STRESS=1'] if args.worker_stress else []),
                       args.image, '/repo/scripts/network-policy/measured_container.py', '/test-input', '/image-input']
            subprocess.run(command, check=True, capture_output=True, timeout=30)
            created.append(runtime_name)
            result = subprocess.run(['docker', 'start', '--attach', runtime_name],
                                    capture_output=True, text=True, timeout=840 if args.worker_stress else 620)
            assert len(result.stdout) <= 131072 and len(result.stderr) <= 65536
            print(result.stdout, end='')
            validate_report(download.stdout + result.stdout, download.stderr + result.stderr, result.returncode, args.worker_stress)
            assert subprocess.check_output(['docker', 'inspect', '--format', '{{.State.ExitCode}}', runtime_name], text=True).strip() == '0', result.stderr[-4096:]
            print(json.dumps({'measuredRoutedSentry': True, 'measuredRootService': True,
                              'workerStressRepetitions': 20 if args.worker_stress else 0,
                              'measuredWorkerDownloads': True,
                              'downloadBinarySHA256': hashlib.sha256((work/'download.test').read_bytes()).hexdigest(),
                              'serviceBinarySHA256': hashlib.sha256((work/'service.test').read_bytes()).hexdigest(),
                              'preLaunchKernelPolicyObserved': True,
                              'closedMeasuredOCIAndGuestStorageQuotas': True,
                              'descriptorOnlyHashVerifiedInputs': True,
                              'exactChildObservationAndMismatchWithdrawal': True,
                              'exclusiveMeasuredJobScopeCleanup': True,
                              'ownedMeasuredLaunchAndAuthorityTermination': True,
                              'durableMeasuredJobScopeRetirement': True,
                              'durableMeasuredBundleRecoveryAndRetirement': True,
                              'closedControllerBundlePreparation': True,
                              'journaledIndependentRouterOwner': True,
                              'allRouterThreadsUnprivileged': True,
                              'ownedPrivateLinkRequiredForLaunchAndEvidence': True,
                              'bornInsideCgroup': True, 'retainedKernelResourceLimits': True,
                              'realProtectedSquashFS': True, 'authorityWithdrawalAndExpiry': True,
                              'liveEndpointsDuringDenial': True, 'noResume': True, 'repetitions': 3,
                              'fixtureImage': args.image, 'builderSHA256': BUILDER_SHA,
                              'rootfsSHA256': hashlib.sha256((work/'image.squashfs').read_bytes()).hexdigest(),
                              'testBinarySHA256': hashlib.sha256((work/'gvisor.test').read_bytes()).hexdigest()}, sort_keys=True))
        finally:
            # Exact newly-created containers only. Never delete unrelated state.
            # On interruption, allow the fixture's bounded process to finish its
            # owned loop cleanup instead of force-killing it mid-mount.
            for name in reversed(created):
                subprocess.run(['docker', 'wait', name], capture_output=True, check=True, timeout=620)
                subprocess.run(['docker', 'rm', name], capture_output=True, check=True, timeout=15)


if __name__ == '__main__':
    main()
