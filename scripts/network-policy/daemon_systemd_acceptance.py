#!/usr/bin/env python3
"""Actual measured daemon launch/restart in a fresh networkless systemd guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


def run(*args, timeout=30):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=timeout).stdout.strip()


def digest(path):
    assert path.is_absolute() and path.resolve() == path and path.is_file()
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    for name in ('rootfs', 'manifest', 'runsc'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--go', required=True)
    args = parser.parse_args()
    assert re.fullmatch('sha256:[a-f0-9]{64}', args.image)
    manifest = json.loads(args.manifest.read_text())
    assert manifest['sha256'] == digest(args.rootfs) and manifest['sizeBytes'] == args.rootfs.stat().st_size
    assert manifest['runnerUid'] == 994 and manifest['runnerGid'] == 981 and manifest['reproducibleBuilds'] == 2
    repo = Path(__file__).resolve().parents[2]
    work = Path(tempfile.mkdtemp(prefix='provenance-daemon-systemd-', dir='/var/tmp'))
    environment = os.environ | {'CGO_ENABLED': '0'}
    subprocess.run([args.go, 'build', '-trimpath', '-buildvcs=false', '-ldflags',
        '-X github.com/bwmp-dev/provenance-runner/internal/buildinfo.Version=0.1.0-alpha',
        '-o', str(work / 'runner'), './cmd/provenance-runner'], cwd=repo, env=environment, check=True, timeout=180)
    subprocess.run([args.go, 'test', '-c', '-o', str(work / 'client.test'), './internal/measuredclient'],
                   cwd=repo, env=environment, check=True, timeout=180)
    container = run('docker', 'create', '--label', 'provenance.fixture=hosted-measured-daemon',
        '--privileged', '--network', 'none', '--cgroupns', 'private', '--memory', '6g',
        '--memory-swap', '6g', '--cpus', '4', '--pids-limit', '1024',
        '--tmpfs', '/run', '--tmpfs', '/run/lock',
        '--mount', f'type=bind,src={work},dst=/inputs,readonly',
        '--mount', f'type=bind,src={args.rootfs},dst=/rootfs-input,readonly',
        '--mount', f'type=bind,src={args.manifest},dst=/manifest-input,readonly',
        '--mount', f'type=bind,src={args.runsc},dst=/runsc-input,readonly', args.image)
    assert re.fullmatch('[a-f0-9]{64}', container)
    print(json.dumps({'fixtureContainer': container, 'evidenceDirectory': str(work),
        'runnerSha256': digest(work / 'runner'), 'clientSha256': digest(work / 'client.test'),
        'runscSha256': digest(args.runsc), 'rootImageSha256': manifest['sha256']}), flush=True)
    successful = False
    try:
        run('docker', 'start', container)
        for _ in range(60):
            result = subprocess.run(['docker', 'exec', container, 'systemctl', 'is-system-running', '--quiet'],
                                    capture_output=True, timeout=10)
            if result.returncode == 0:
                break
            time.sleep(0.5)
        assert result.returncode == 0
        for name in ('measured-service-launch.py', 'measured-rootfs-boot.py', 'runtime-generation.py',
                     'measured-storage.py', 'measured-host-inventory.py', 'test-measured-daemon-systemd-fixture.py'):
            run('docker', 'cp', str(repo / 'scripts' / name), container + ':/opt/' + name)
        run('docker', 'exec', container, 'python3', '-I', '-c',
            'from pathlib import Path; p=Path("/run/provenance-daemon-disposable"); '
            'f=p.open("x"); f.write("hosted-daemon-disposable-only\\n"); f.close()')
        result = subprocess.run(['docker', 'exec', container, 'python3', '-I',
            '/opt/test-measured-daemon-systemd-fixture.py'], capture_output=True, text=True, timeout=300)
        assert len(result.stdout) <= 131072 and len(result.stderr) <= 16384
        print(result.stdout, end='', flush=True)
        assert result.returncode == 0, result.stderr[-8192:]
        assert result.stdout.count('--- PASS: TestHostedMeasuredSystemdReadiness ') == 3
        assert '"actualHostedDaemonReadinessAndRestart": true' in result.stdout
        assert '"hostedDaemonOwnedMountsLoopsAndGroupsAbsent": true' in result.stdout
        successful = True
    finally:
        assert run('docker', 'inspect', '--format', '{{index .Config.Labels "provenance.fixture"}}', container) == 'hosted-measured-daemon'
        run('docker', 'stop', '--timeout', '20', container)
        assert run('docker', 'inspect', '--format', '{{.State.Running}}', container) == 'false'
        if successful:
            run('docker', 'rm', container)
            print(json.dumps({'exactHostedDaemonContainerRemoved': True}), flush=True)
        else:
            print(json.dumps({'stoppedHostedDaemonGuestRetained': container}), flush=True)


if __name__ == '__main__':
    main()
