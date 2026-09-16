#!/usr/bin/env python3
"""Real Paper compatibility in a fresh measured gVisor fixture; no deployment."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

ROOT = '6d0a79fcd156c39a1b362cc4295367989ef72ccbb6a475aad399228b3211c32e'
SECRET_TARGET = 'b84160a378c4e0eaa5f8ada6b0b05a825791c2baf89d11aff5304bf3f923a4b1'
HELPER = '69991043ce8c4c640163d70e484b4b1af009f3e82bc6e847d97815a464b81275'
INPUTS = {'java.tar.gz': '968c283e104059dae86ea1d670672a80170f27a39529d815843ec9c1f0fa2a03',
          'paper.jar': '8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e',
          'target.jar': 'a0c881f0a9e2229143ae8cfcc5fd019de02ce96504fe66c29f90eb13aad004ba',
          'prepared-runtime.tar.gz': 'bd8ba32e4ec988a09335b868a9585c94ca75600e445f37825fd8339bee45d69c'}


def digest(path):
    assert not path.is_symlink() and path.is_file()
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def validate_report(stdout, stderr, code, gateway=False, secrets=False):
    assert len(stdout) <= 65536 and len(stderr) <= 65536
    assert code == 0, stderr[-4096:]
    assert '--- SKIP:' not in stdout and '--- FAIL:' not in stdout
    if gateway:
        assert stdout.count('MEASURED_GATEWAY_PAPER_TERMINAL_OK') == 3
        if secrets:
            assert stdout.count('MEASURED_GATEWAY_PAPER_SECRETS_OK') == 3
    for suffix in ('', '/root-config-permissions', '/root-config-pin-refusal', '/root-idle-barrier-after-retirement'):
        assert stdout.count('--- PASS: TestMeasuredPaperRealKernel'+suffix+' ') == 3
    for marker in ('measuredRealPaperCompatibility', 'measuredHostUplinkJournalRetired', 'measuredBundleJournalRetired', 'measuredJobJournalRetired', 'exclusiveMeasuredJobScopesRemoved', 'measuredRoutedOwnedLoopDetached'):
        assert '{"'+marker+'": true}' in stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--secrets', action='store_true')
    parser.add_argument('--gateway', action='store_true')
    args = parser.parse_args()
    assert re.fullmatch('sha256:[a-f0-9]{64}', args.image)
    assert args.rootfs.is_absolute() and args.rootfs.resolve() == args.rootfs and digest(args.rootfs) == ROOT
    assert args.inputs.is_absolute() and args.inputs.resolve() == args.inputs
    for name, expected in INPUTS.items():
        assert digest(args.inputs/name) == expected and (args.inputs/name).stat().st_size <= 256 << 20
    if args.secrets:
        assert digest(args.inputs/'secret-target.jar') == SECRET_TARGET and (args.inputs/'secret-target.jar').stat().st_size <= 1 << 20
    repo = Path(__file__).resolve().parents[2]
    work = Path(tempfile.mkdtemp(prefix='provenance-real-paper-', dir='/var/tmp'))
    environment = os.environ | {'CGO_ENABLED': '0'}
    for name, package in [('gvisor', './internal/provider/gvisor'), ('service', './internal/measuredservice'), ('download', './internal/provider/paper')]:
        subprocess.run([args.go, 'test', '-c', '-ldflags', '-X github.com/bwmp-dev/provenance-runner/internal/buildinfo.Version=0.1.0-alpha', '-o', str(work/(name+'.test')), package], cwd=repo, env=environment, check=True, timeout=180)
    name = 'provenance-real-paper-'+uuid.uuid4().hex
    command = ['docker', 'create', '--name', name, '--privileged', '--network', 'none', '--cgroupns', 'private', '--read-only',
               '--memory', '6g', '--memory-swap', '6g', '--cpus', '4', '--pids-limit', '1024',
               '--tmpfs', '/tmp:rw,exec,nosuid,size=1536m',
               '--env', 'PROVENANCE_DISPOSABLE_REAL_PAPER_FIXTURE=1',
               '--env', 'PROVENANCE_DISPOSABLE_GATEWAY_FIXTURE='+('1' if args.gateway else '0'),
               '--env', 'PROVENANCE_DISPOSABLE_REAL_PAPER_SECRETS='+('1' if args.secrets else '0'),
               '--mount', f'type=bind,src={repo},dst=/repo,readonly',
               '--mount', f'type=bind,src={work}/gvisor.test,dst=/test-input,readonly',
               '--mount', f'type=bind,src={args.rootfs},dst=/image-input,readonly',
               '--mount', f'type=bind,src={args.inputs},dst=/paper-fixture,readonly',
               '--mount', f'type=bind,src={work},dst=/state-input',
               args.image, '/repo/scripts/network-policy/measured_container.py', '/test-input', '/image-input']
    subprocess.run(command, capture_output=True, check=True, timeout=30)
    print(json.dumps({'fixtureContainer': name, 'evidenceDirectory': str(work)}), flush=True)
    result = subprocess.run(['docker', 'start', '--attach', name], capture_output=True, text=True, timeout=940)
    print(result.stdout, end='', flush=True)
    state = json.loads(subprocess.check_output(['docker', 'inspect', '--format', '{{json .State}}', name], text=True, timeout=15))
    # Preserve all staged evidence. Remove the exact disposable container only
    # after its own loop retirement has been positively observed.
    if '{"measuredRoutedOwnedLoopDetached": true}' in result.stdout:
        subprocess.run(['docker', 'rm', name], capture_output=True, check=True, timeout=30)
    validate_report(result.stdout, result.stderr, result.returncode, args.gateway, args.secrets)
    assert state['Status'] == 'exited' and state['ExitCode'] == 0 and not state['OOMKilled']
    print(json.dumps({'realPaperCompatibility': True, 'gameVersion': '1.21.8', 'paperBuild': 60, 'repetitions': 3,
                      'rootfsSHA256': ROOT, 'paperGuestSHA256': HELPER, 'inputs': INPUTS,
                      'serviceBinarySHA256': digest(work/'service.test'), 'workerBinarySHA256': digest(work/'download.test'),
                      'fixtureImage': args.image, 'deployed': False}, sort_keys=True))
    if args.secrets:
        print(json.dumps({'realPaperSecretInjectionAndRedaction': True, 'targetSHA256': SECRET_TARGET, 'repetitions': 3, 'deployed': False}, sort_keys=True))
    if args.gateway:
        print(json.dumps({'realPaperGatewayTerminalEvidence': True, 'gatewaySecretDeliveryAndRedaction': args.secrets, 'repetitions': 3, 'platformDatabaseAcceptance': False, 'objectStorageAcceptance': False, 'deployed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
