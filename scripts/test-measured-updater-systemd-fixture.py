#!/usr/bin/env python3
"""Signed swaps with a real daemon/systemd and synthetic coordinator replies."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import uuid
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('updater', '/opt/updater.py')
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


def write(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as file:
        file.write(raw)


def probe():
    raw = u.run('runuser', '-u', 'provenance-worker', '--', 'env',
                'PROVENANCE_DISPOSABLE_HOSTED_DAEMON=1', '/opt/client.test', '-test.v',
                '-test.run=^TestHostedMeasuredSystemdReadiness$', '-test.count=1')
    assert b'--- PASS: TestHostedMeasuredSystemdReadiness ' in raw and b'SKIP' not in raw


class Coordinator:
    """No socket or credentials: only coordinator transport/health is synthetic."""
    def __init__(self, release, binary, rejected=False):
        self.release, self.binary, self.rejected = release, binary, rejected
        self.operation = str(uuid.uuid4())
        self.probes = 0

    def poll(self, operation='', report='idle'):
        if not operation:
            return {'phase': 'install', 'operationId': self.operation, 'release': self.release}
        assert operation == self.operation
        if report in ('succeeded', 'rolled_back', 'failed'):
            return {'phase': 'complete', 'outcome': report}
        if report in ('verifying', 'rollback-health'):
            probe()
            self.probes += 1
            return {'healthy': not self.rejected or report == 'rollback-health'}
        return {'phase': 'verify'}

    def download(self, release, destination):
        assert release == self.release and hashlib.sha256(self.binary).hexdigest() == release['sha256']
        write(destination, self.binary)


def exercise():
    assert os.geteuid() == 0 and Path('/.dockerenv').is_file()
    assert os.environ.get('PROVENANCE_DISPOSABLE_MEASURED_UPDATER') == '1'
    original = (u.ROOT / 'runner').read_bytes()
    u.WORK.mkdir(mode=0o700)
    u.STATE.mkdir(mode=0o700)
    (u.STATE / 'config').mkdir(mode=0o700)
    write(u.STATE / 'config/.provenance-runner-journal.json', b'{"schemaVersion":"provenance.runner-journal/v1alpha1"}')
    write(u.ROOT / 'installed.json', json.dumps({'runnerSha256': hashlib.sha256(original).hexdigest()}).encode())
    unit = Path('/etc/systemd/system/provenance-runner.service')
    write(unit, b'[Unit]\nRequires=provenance-measured.service\nAfter=provenance-measured.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n', 0o644)
    u.run('systemctl', 'daemon-reload')
    u.service('start')
    probe()
    key = u.WORK / 'fixture-key.pem'
    u.run('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key))
    key.chmod(0o600)
    public = u.run('openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER')[-32:]
    accepted = None
    try:
        for index, scenario in enumerate(('success', 'health-rollback', 'crash-rollback')):
            # ELF permits an appended fixture marker. Both bytes remain the
            # same real daemon implementation but have distinct measured hashes.
            binary = original + ('\nmeasured-update-fixture-' + scenario + '\n').encode()
            release = {'version': 'fixture.' + str(index), 'url': 'https://fixtures.example.com/runner',
                       'sha256': hashlib.sha256(binary).hexdigest(), 'sizeBytes': len(binary), 'signature': ''}
            message, signature = u.WORK / ('message-' + str(index)), u.WORK / ('signature-' + str(index))
            write(message, u.signing_bytes(release))
            u.run('openssl', 'pkeyutl', '-sign', '-inkey', str(key), '-rawin', '-in', str(message), '-out', str(signature))
            release['signature'] = base64.b64encode(signature.read_bytes()).decode()
            coordinator = Coordinator(release, binary, rejected=scenario == 'health-rollback')
            updater = u.Updater({'releasePublicKey': base64.b64encode(public).decode()}, coordinator)
            if scenario == 'crash-rollback':
                atomic = u.atomic
                def crash(path, *args, **kwargs):
                    atomic(path, *args, **kwargs)
                    if path == u.MEASURED_CONFIG:
                        raise SystemExit('simulated process death after config replacement')
                try:
                    with patch.object(u, 'atomic', side_effect=crash):
                        updater.step()
                except SystemExit:
                    pass
                else:
                    raise AssertionError('fixture did not interrupt the switch')
                assert u.sha(u.ROOT / 'runner') == release['sha256']
                assert json.loads(u.MEASURED_CONFIG.read_bytes())['runnerSha256'] == release['sha256']
                assert json.loads(u.MEASURED_PLAN.read_bytes())['runner']['sha256'] == hashlib.sha256(accepted).hexdigest()
                assert not u.MEASURED_CGROUP.exists()
            with patch.object(u.time, 'sleep', return_value=None):
                # Health sampling is accelerated; actual signature checks,
                # filesystem writes, systemd stops and daemon probes are real.
                updater.step()
            journal = json.loads(updater.journal.read_bytes())
            assert journal['phase'] == 'complete'
            assert journal['report'] == ('succeeded' if scenario == 'success' else 'rolled_back')
            if scenario == 'success':
                accepted = binary
            assert (u.ROOT / 'runner').read_bytes() == accepted
            expected = hashlib.sha256(accepted).hexdigest()
            assert json.loads(u.MEASURED_CONFIG.read_bytes())['runnerSha256'] == expected
            assert json.loads(u.MEASURED_PLAN.read_bytes())['runner']['sha256'] == expected
            assert coordinator.probes >= 3
            probe()
        print(json.dumps({'signedMeasuredUpdateAndRollback': True, 'actualDaemonAndSystemd': True,
            'syntheticCoordinator': True, 'actualWorkerProcess': False, 'crashAfterConfigRecovered': True,
            'signatureChecksBypassed': False, 'productionChanged': False}))
    finally:
        u.service('stop')
        assert not u.MEASURED_CGROUP.exists()
