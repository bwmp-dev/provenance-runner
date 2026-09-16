#!/usr/bin/env python3
"""Root-owned binary updater for the operator's hosted fleet only."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
import uuid

ROOT = Path('/opt/provenance-runner')
STATE = Path('/var/lib/provenance-runner')
WORK = ROOT/'update-state'
UNIT = 'provenance-runner.service'
USER = 'provenance-worker'
MEASURED_PLAN = Path('/etc/provenance/measured-launch.json')
MEASURED_CONFIG = Path('/etc/provenance/measured-service.json')
MEASURED_UNIT = 'provenance-measured.service'
MEASURED_CGROUP = Path('/sys/fs/cgroup/system.slice/provenance-measured.service')
MAX_BINARY = 512*1024**2
MAX_CATALOG = 256*1024
USER_AGENT = 'Provenance-Hosted-Updater/1.0 (https://provenance.bwmp.dev)'


def check(ok, message):
    if not ok:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, 'Duplicate JSON field')
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique)


def protected(path):
    check(path.is_absolute() and path.resolve() == path, 'Unsafe operator path')
    for p in (path, *path.parents):
        s = p.lstat()
        check(s.st_uid == 0 and not s.st_mode & 0o7022 and not stat.S_ISLNK(s.st_mode), 'Unprotected operator input')
    s = path.stat()
    check(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'Operator input must be a single-link file')


def read(path, limit=65536):
    protected(path)
    check(path.stat().st_size <= limit, 'Operator input exceeds limit')
    return path.read_bytes()


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def atomic(path, data, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix='.update-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            os.fchmod(f.fileno(), mode)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run(*args):
    result = subprocess.run(args, capture_output=True, timeout=180)
    check(result.returncode == 0, 'Local update operation failed: '+Path(args[0]).name)
    return result.stdout


def signing_bytes(release):
    check(set(release) == {'version', 'url', 'sha256', 'sizeBytes', 'signature'}, 'Unsupported release fields')
    check(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}', release['version']), 'Invalid release version')
    check(re.fullmatch(r'[a-f0-9]{64}', release['sha256']), 'Invalid release digest')
    check(type(release['sizeBytes']) is int and 0 < release['sizeBytes'] <= MAX_BINARY, 'Invalid release size')
    u = urlsplit(release['url'])
    check(u.scheme == 'https' and u.hostname and not u.username and not u.password and not u.query
          and not u.fragment and len(release['url']) <= 2048 and not any(c.isspace() for c in release['url']), 'Invalid release URL')
    return ('provenance.hosted-runner-release/v1\n' + ''.join(f'{k}:{release[k]}\n' for k in ('version', 'url', 'sha256', 'sizeBytes'))).encode()


def verify_release(release, public_key):
    message = signing_bytes(release)
    signature = base64.b64decode(release['signature'], validate=True)
    key = base64.b64decode(public_key, validate=True)
    check(len(signature) == 64 and len(key) == 32, 'Invalid signing material')
    # Ed25519 SPKI prefix. Key never comes from the downloaded release.
    with tempfile.TemporaryDirectory(dir=WORK) as temp:
        p = Path(temp)
        (p/'key.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+key)
        (p/'signature').write_bytes(signature)
        (p/'message').write_bytes(message)
        run('openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', str(p/'key.der'),
            '-rawin', '-in', str(p/'message'), '-sigfile', str(p/'signature'))


def catalog_signing_bytes(revision):
    check(set(revision) == {'schemaVersion', 'artifactHosts', 'catalogs', 'sha256', 'signature'}, 'Unsupported catalog fields')
    check(revision['schemaVersion'] == 'provenance.hosted-paper-catalog/v1', 'Invalid catalog schema')
    check(isinstance(revision['artifactHosts'], list) and 0 < len(revision['artifactHosts']) <= 32
          and revision['artifactHosts'] == sorted(set(revision['artifactHosts'])), 'Invalid catalog artifact hosts')
    check(isinstance(revision['catalogs'], list) and 0 < len(revision['catalogs']) <= 32, 'Invalid catalog entries')
    check([entry.get('environmentId') for entry in revision['catalogs']] == sorted(entry.get('environmentId') for entry in revision['catalogs']), 'Catalog entries are not canonical')
    payload = {key: revision[key] for key in ('schemaVersion', 'artifactHosts', 'catalogs')}
    canonical = json.dumps(payload, separators=(',', ':'), ensure_ascii=False, sort_keys=True).encode()
    check(len(canonical) <= MAX_CATALOG and re.fullmatch(r'[a-f0-9]{64}', revision['sha256'])
          and hashlib.sha256(canonical).hexdigest() == revision['sha256'], 'Catalog canonical digest mismatch')
    for catalog in revision['catalogs']:
        check(set(catalog) == {'environmentId', 'paper', 'java', 'probeVersion', 'probeSourceCommit', 'probe', 'preparedRuntime'}, 'Invalid catalog entry')
        assets = (catalog['paper']['artifact'], catalog['java']['artifact'], catalog['probe'], catalog['preparedRuntime']['artifact'])
        for asset in assets:
            check(set(asset) == {'uri', 'sha256', 'filename', 'sizeBytes'}, 'Invalid catalog artifact')
            check(re.fullmatch(r'[a-f0-9]{64}', asset['sha256']) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,199}', asset['filename'])
                  and type(asset['sizeBytes']) is int and 0 < asset['sizeBytes'] <= MAX_BINARY, 'Invalid catalog artifact identity')
            parsed = urlsplit(asset['uri'])
            check(parsed.scheme == 'https' and parsed.hostname in revision['artifactHosts'] and not parsed.username and not parsed.password
                  and not parsed.query and not parsed.fragment and parsed.path == '/v1/runner-catalog-assets/'+asset['sha256']+'/'+asset['filename'], 'Invalid catalog asset URL')
    return ('provenance.hosted-paper-catalog/v1\nsha256:'+revision['sha256']+'\n').encode()


def verify_catalog(revision, public_key):
    message = catalog_signing_bytes(revision)
    signature = base64.b64decode(revision['signature'], validate=True)
    key = base64.b64decode(public_key, validate=True)
    check(len(signature) == 64 and len(key) == 32, 'Invalid catalog signing material')
    with tempfile.TemporaryDirectory(dir=WORK) as temp:
        p = Path(temp)
        (p/'key.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+key)
        (p/'signature').write_bytes(signature)
        (p/'message').write_bytes(message)
        run('openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', str(p/'key.der'),
            '-rawin', '-in', str(p/'message'), '-sigfile', str(p/'signature'))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Update endpoints must not redirect')


class Client:
    def __init__(self, config):
        self.config = config
        self.token = read(Path(config['credentialFile']), 128).decode().strip()
        check(re.fullmatch(r'pru_[a-f0-9]{64}', self.token), 'Invalid updater credential')
        self.opener = urllib.request.build_opener(NoRedirect())

    def poll(self, operation='', report='idle'):
        body = json.dumps({'operationId': operation, 'report': report}).encode()
        url = self.config['apiOrigin']+'/v1/runner-updater/'+self.config['runnerId']+'/poll'
        request = urllib.request.Request(url, data=body, headers={'Authorization': 'Bearer '+self.token, 'Content-Type': 'application/json', 'User-Agent': USER_AGENT}, method='POST')
        with self.opener.open(request, timeout=30) as response:
            data = response.read(65537)
        check(len(data) <= 65536, 'Oversized update command')
        result = decode(data)
        check(set(result) == {'operationId', 'phase', 'release', 'previousVersion', 'healthy', 'outcome'}, 'Invalid update command')
        check(result['phase'] in ('wait', 'install', 'verify', 'complete'), 'Invalid update phase')
        check(result['phase'] == 'wait' or bool(result['operationId']), 'Missing operation identity')
        if result['operationId']:
            check(str(uuid.UUID(result['operationId'])) == result['operationId'], 'Invalid operation identity')
        if operation:
            check(result['operationId'] == operation, 'Update operation identity changed')
        return result

    def download(self, release, destination):
        headers = {'User-Agent': USER_AGENT}
        origin = self.config['apiOrigin']
        if release['url'] == origin+'/v1/runner-releases/'+release['sha256']:
            headers['Authorization'] = 'Bearer '+self.token
        request = urllib.request.Request(release['url'], headers=headers)
        count = 0
        digest = hashlib.sha256()
        with self.opener.open(request, timeout=60) as response, destination.open('xb') as output:
            while True:
                chunk = response.read(min(1024**2, release['sizeBytes']-count+1))
                if not chunk:
                    break
                count += len(chunk)
                check(count <= release['sizeBytes'], 'Release exceeds signed size')
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        check(count == release['sizeBytes'] and digest.hexdigest() == release['sha256'], 'Release bytes do not match signature')
        with destination.open('rb') as f:
            h = f.read(20)
        check(h[:5] == b'\x7fELF\x02' and h[5] == 1 and h[18:20] == b'\x3e\x00', 'Release is not Linux amd64 ELF')
        destination.chmod(0o755)

    def catalog_poll(self, operation='', report='idle'):
        body = json.dumps({'operationId': operation, 'report': report}).encode()
        url = self.config['apiOrigin']+'/v1/runner-catalogs/'+self.config['runnerId']+'/poll'
        request = urllib.request.Request(url, data=body, headers={'Authorization': 'Bearer '+self.token, 'Content-Type': 'application/json', 'User-Agent': USER_AGENT}, method='POST')
        with self.opener.open(request, timeout=30) as response:
            data = response.read(MAX_CATALOG+1)
        check(len(data) <= MAX_CATALOG, 'Oversized catalog command')
        result = decode(data)
        check(set(result) == {'operationId', 'phase', 'revision', 'previousCatalogSha256', 'healthy', 'outcome'}, 'Invalid catalog command')
        check(result['phase'] in ('wait', 'install', 'verify', 'complete'), 'Invalid catalog phase')
        check(result['phase'] == 'wait' or bool(result['operationId']), 'Missing catalog operation identity')
        if result['operationId']:
            check(str(uuid.UUID(result['operationId'])) == result['operationId'], 'Invalid catalog operation identity')
        if operation:
            check(result['operationId'] == operation, 'Catalog operation identity changed')
        return result

    def download_catalog_asset(self, asset, destination):
        expected_prefix = self.config['apiOrigin']+'/v1/runner-catalog-assets/'
        check(asset['uri'] == expected_prefix+asset['sha256']+'/'+asset['filename'], 'Catalog asset is outside assigned API authority')
        request = urllib.request.Request(asset['uri'], headers={'Authorization': 'Bearer '+self.token, 'User-Agent': USER_AGENT})
        count, digest = 0, hashlib.sha256()
        with self.opener.open(request, timeout=300) as response, destination.open('xb') as output:
            while True:
                chunk = response.read(min(1024**2, asset['sizeBytes']-count+1))
                if not chunk: break
                count += len(chunk)
                check(count <= asset['sizeBytes'], 'Catalog asset exceeds signed size')
                digest.update(chunk); output.write(chunk)
            output.flush(); os.fsync(output.fileno())
        check(count == asset['sizeBytes'] and digest.hexdigest() == asset['sha256'], 'Catalog asset bytes do not match pin')
        destination.chmod(0o400)

def local_quiet():
    # Traverse from the root-owned state directory without following any
    # runtime-user-created symlink. No journal content is logged or transmitted.
    root = os.open(STATE, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        config = os.open('config', os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        try:
            journal = os.open('.provenance-runner-journal.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=config)
            with os.fdopen(journal, 'rb') as file:
                s = os.fstat(file.fileno())
                check(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= 256*1024, 'Invalid runner journal')
                value = decode(file.read(256*1024+1))
        finally:
            os.close(config)
    finally:
        os.close(root)
    check(value.get('schemaVersion') == 'provenance.runner-journal/v1alpha1', 'Unsupported runner journal')
    return not any(value.get(k) for k in ('active', 'pendingMessage', 'credentialRotation'))


def service(action):
    run('systemctl', action, UNIT)
    if action == 'stop' and measured_enabled():
        # The worker has stopped and closed its authenticated control channel.
        # Wait for the root owner too; user-manager scopes cannot prove that
        # root-owned job children and persistent cleanup are complete.
        run('systemctl', 'stop', MEASURED_UNIT)
        check(run('systemctl', 'show', MEASURED_UNIT, '--property=ActiveState', '--value').strip()
              in (b'inactive', b'failed') and not MEASURED_CGROUP.exists(),
              'Measured controller has not retired its owned groups')


def measured_enabled():
    present = [path.exists() or path.is_symlink() for path in (MEASURED_PLAN, MEASURED_CONFIG)]
    check(present[0] == present[1], 'Incomplete measured provisioning')
    return all(present)


def measured_private(path):
    raw = read(path)
    info = path.stat()
    check(info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'Measured configuration custody')
    return raw


def measured_snapshot(operation, old_hash, new_hash):
    if not measured_enabled():
        return None
    check(str(uuid.UUID(operation)) == operation, 'Invalid measured update identity')
    before = {'plan': measured_private(MEASURED_PLAN), 'config': measured_private(MEASURED_CONFIG)}
    plan, config = decode(before['plan']), decode(before['config'])
    check(type(plan['version']) is int and plan['version'] == 1 and
          type(config['version']) is int and config['version'] == 1 and
          plan['runner'] == {'path': str(ROOT/'runner'), 'sha256': old_hash} and
          plan['config'] == {'path': str(MEASURED_CONFIG), 'sha256': hashlib.sha256(before['config']).hexdigest()} and
          config['runnerSha256'] == old_hash, 'Measured before-image binding')
    requirements = run('systemctl', 'show', UNIT, '--property=Requires', '--value').decode().split()
    check(MEASURED_UNIT in requirements, 'Worker must require measured controller readiness')
    for name, pin in plan.items():
        if name == 'version':
            continue
        check(isinstance(pin, dict) and set(pin) == {'path', 'sha256'}, 'Measured launch pin')
        path = Path(pin['path'])
        protected(path)
        check(path.stat().st_size <= MAX_BINARY and sha(path) == pin['sha256'], 'Measured launch input drift')
    config['runnerSha256'] = new_hash
    after = {'config': (json.dumps(config, sort_keys=True, separators=(',', ':'))+'\n').encode()}
    plan['runner']['sha256'] = new_hash
    plan['config']['sha256'] = hashlib.sha256(after['config']).hexdigest()
    after['plan'] = (json.dumps(plan, sort_keys=True, separators=(',', ':'))+'\n').encode()
    directory = WORK/('measured-'+operation)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass  # An interrupted pre-journal staging may be resumed only exactly.
    check(directory.resolve() == directory and directory.is_dir() and
          stat.S_IMODE(directory.stat().st_mode) == 0o700, 'Measured snapshot directory')
    record = {'version': 1, 'directory': directory.name, 'oldSha256': old_hash, 'newSha256': new_hash}
    for state, items in (('before', before), ('after', after)):
        record[state] = {}
        for name, raw in items.items():
            target = directory/(state+'-'+name+'.json')
            if not target.exists() and not target.is_symlink():
                # Exclusive creation prevents a retry from replacing evidence.
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as file:
                    file.write(raw)
                    file.flush()
                    os.fsync(file.fileno())
            check(measured_private(target) == raw, 'Retained measured snapshot drift')
            record[state][name] = hashlib.sha256(raw).hexdigest()
    for path in (directory, WORK):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return record


def measured_projection(op, expected):
    record = op.get('measured') if op else None
    check(bool(record) == measured_enabled(), 'Measured transaction/provisioning mismatch')
    if not record:
        return None
    check(set(record) == {'version', 'directory', 'oldSha256', 'newSha256', 'before', 'after'} and
          type(record['version']) is int and record['version'] == 1 and
          str(uuid.UUID(op['id'])) == op['id'] and record['directory'] == 'measured-'+op['id'] and
          record['oldSha256'] == op['oldSha256'] and record['newSha256'] == op['release']['sha256'] and
          expected in (record['oldSha256'], record['newSha256']), 'Measured transaction identity')
    snapshots = {}
    for state in ('before', 'after'):
        check(set(record[state]) == {'plan', 'config'}, 'Measured snapshot fields')
        snapshots[state] = {}
        for name in ('plan', 'config'):
            raw = measured_private(WORK/record['directory']/(state+'-'+name+'.json'))
            check(hashlib.sha256(raw).hexdigest() == record[state][name], 'Measured snapshot digest')
            snapshots[state][name] = raw
    # Exactly the old/new images are legal, including a crash between either
    # atomic JSON replacement. Never rewrite an unrelated operator edit.
    for name, path in (('plan', MEASURED_PLAN), ('config', MEASURED_CONFIG)):
        check(measured_private(path) in (snapshots['before'][name], snapshots['after'][name]),
              'Unrecognized measured mixed state')
    check(sha(ROOT/'runner') in (record['oldSha256'], record['newSha256']), 'Unrecognized measured binary')
    check(run('systemctl', 'show', MEASURED_UNIT, '--property=ActiveState', '--value').strip()
          in (b'inactive', b'failed') and not MEASURED_CGROUP.exists(), 'Measured owner must be stopped')
    return snapshots['before' if expected == record['oldSha256'] else 'after']


def no_scopes():
    uid = run('id', '-u', USER).decode().strip()
    check(re.fullmatch(r'[1-9][0-9]*', uid), 'Invalid worker account identity')
    scopes = run('runuser', '-u', USER, '--', 'env', f'XDG_RUNTIME_DIR=/run/user/{uid}',
                 f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus', 'systemctl', '--user',
                 'list-units', '--type=scope', '--state=active,activating,deactivating', '--no-legend', '--plain').strip()
    # Every systemd user manager owns init.scope for the manager itself.
    # It is not a sandbox; all other listed scopes still block replacement.
    rows = [line.split() for line in scopes.splitlines() if line.strip()]
    check(not rows or (len(rows) == 1 and rows[0][:4] == [b'init.scope', b'loaded', b'active', b'running']),
          'Active sandbox scopes prevent replacement')


class Updater:
    def __init__(self, config, client):
        self.config, self.client = config, client
        self.journal = WORK/'operation.json'

    def save(self, op):
        atomic(self.journal, json.dumps(op).encode())

    def metadata(self, binary_hash):
        metadata = decode(read(ROOT/'installed.json'))
        metadata['runnerSha256'] = binary_hash
        # sourceCommit describes the original installer. The signed release is
        # retained in the update journal for the selected binary's identity.
        atomic(ROOT/'installed.json', json.dumps(metadata).encode())

    def switch(self, source, expected, op=None):
        protected(source)
        check(sha(source) == expected, 'Retained binary identity changed')
        projection = measured_projection(op, expected)
        atomic(ROOT/'runner', source.read_bytes(), 0o755)
        self.metadata(expected)
        if projection:
            atomic(MEASURED_CONFIG, projection['config'])
            atomic(MEASURED_PLAN, projection['plan'])

    def healthy(self, op, report):
        consecutive = 0
        for _ in range(30):
            try:
                response = self.client.poll(op['id'], report)
                consecutive = consecutive + 1 if response['healthy'] else 0
                if consecutive >= 3:
                    return True
            except (OSError, ValueError):
                consecutive = 0
            time.sleep(2)
        return False

    def finish(self, op, report):
        # Persist intent before the backend can resume admission. Recovery must
        # resolve this report, never blindly stop a node that may have new jobs.
        op['phase'] = 'committing'
        op['report'] = report
        self.save(op)
        result = self.client.poll(op['id'], report)
        check(result['phase'] == 'complete' and result['outcome'] == report, 'Terminal update report is not committed')
        op['phase'] = 'complete'
        self.save(op)

    def rollback(self, op):
        op['phase'] = 'rollback'
        self.save(op)
        no_scopes()  # Refuse known active scopes before stopping the retained worker.
        service('stop')
        if not local_quiet():
            service('start')
            return  # Let the retained worker flush its journal while still drained.
        no_scopes()
        self.switch(WORK/(op['oldSha256']+'.elf'), op['oldSha256'], op)
        service('start')
        if self.healthy(op, 'rollback-health'):
            self.finish(op, 'rolled_back')
        else:
            self.finish(op, 'failed')  # Backend retains drain; never auto-resume an unhealthy node.

    def step(self):
        if self.journal.exists():
            op = decode(read(self.journal))
            if op['phase'] == 'committing':
                self.finish(op, op['report'])
                return
            if op['phase'] != 'complete':
                # Resolve backend truth before any crash-recovery stop operation.
                result = self.client.poll(op['id'])
                if result['phase'] == 'complete':
                    check(result['outcome'] in ('succeeded', 'rolled_back', 'failed'), 'Unexpected terminal update')
                    op['phase'] = 'complete'
                    self.save(op)
                    return
                self.rollback(op)
                return
        command = self.client.poll()
        if command['phase'] != 'install':
            return
        try:
            release = command['release']
            verify_release(release, self.config['releasePublicKey'])
            if not local_quiet():
                return
            no_scopes()  # Rechecked after stop; preflight refusal leaves the worker running.
            # Immutable backups are addressed by their verified complete bytes.
            protected(ROOT/'runner')
            old_hash = sha(ROOT/'runner')
            check(decode(read(ROOT/'installed.json'))['runnerSha256'] == old_hash, 'Installed runner identity drift')
            backup = WORK/(old_hash+'.elf')
            if not backup.exists():
                atomic(backup, (ROOT/'runner').read_bytes(), 0o755)
            check(sha(backup) == old_hash, 'Rollback binary drift')
            target = WORK/(release['sha256']+'.elf')
            if not target.exists():
                with tempfile.TemporaryDirectory(dir=WORK) as temp:
                    downloaded = Path(temp)/'runner'
                    self.client.download(release, downloaded)
                    atomic(target, downloaded.read_bytes(), 0o755)
            check(sha(target) == release['sha256'], 'Staged binary drift')
            measured = measured_snapshot(command['operationId'], old_hash, release['sha256'])
        except (ValueError, TypeError, KeyError):
            self.client.poll(command['operationId'], 'failed')
            return  # No binary was replaced; backend retains drain for inspection.
        op = {'id': command['operationId'], 'release': release, 'oldSha256': old_hash, 'phase': 'staged'}
        if measured:
            op['measured'] = measured
        self.save(op)
        try:
            service('stop')
            check(local_quiet(), 'Pending terminal replay prevents update')
            no_scopes()
            self.switch(target, release['sha256'], op)
            op['phase'] = 'verifying'
            self.save(op)
            service('start')
            if self.healthy(op, 'verifying'):
                self.finish(op, 'succeeded')
            else:
                self.rollback(op)
        except Exception:
            # Once terminal reporting starts, admission might already be active.
            current = decode(read(self.journal))
            if current['phase'] not in ('committing', 'complete'):
                self.rollback(current)
            else:
                raise


class CatalogReconciler:
    """Crash-safe catalog desired-state transaction for a drained hosted node."""
    def __init__(self, config, client):
        self.config, self.client = config, client
        self.journal = WORK/'catalog-operation.json'

    def save(self, operation):
        atomic(self.journal, json.dumps(operation).encode())

    def healthy(self, operation, report):
        consecutive = 0
        for _ in range(30):
            try:
                response = self.client.catalog_poll(operation['id'], report)
                consecutive = consecutive + 1 if response['healthy'] else 0
                if consecutive >= 3: return True
            except (OSError, ValueError):
                consecutive = 0
            time.sleep(2)
        return False

    def finish(self, operation, report):
        operation['phase'], operation['report'] = 'committing', report
        self.save(operation)
        result = self.client.catalog_poll(operation['id'], report)
        check(result['phase'] == 'complete' and result['outcome'] == report, 'Terminal catalog report is not committed')
        operation['phase'] = 'complete'
        self.save(operation)

    def catalog_environment(self, current, catalogs):
        check(len(current) <= MAX_CATALOG*2 and b'\0' not in current and b'\r' not in current
              and (not current or current.endswith(b'\n')), 'Invalid installed environment encoding or bound')
        names, retained = set(), []
        for line in current.splitlines(keepends=True):
            if not line.strip() or line.startswith((b'#', b';')):
                retained.append(line)
                continue
            match = re.fullmatch(rb'([A-Z][A-Z0-9_]*)=([^\n]*)\n', line)
            check(match is not None, 'Invalid installed environment field')
            name, value = match[1].decode('ascii'), match[2].decode('utf-8')
            check(name not in names, 'Duplicate installed environment field')
            names.add(name)
            # Same narrow single-line grammar as measured boot selection. Never
            # make hidden assignments effective by removing a continuation or
            # an unterminated quoted catalog line during reconciliation.
            if value.startswith('"'):
                check(isinstance(json.loads(value), str), 'Invalid installed environment string')
            else:
                check(re.fullmatch(r'[A-Za-z0-9_:/.,@+=%-]*', value), 'Invalid installed environment value')
            owned = (name == 'PROVENANCE_PAPER_CATALOGS_JSON' or name.startswith('PROVENANCE_PAPER_PROBE_')
                     or name.startswith('PROVENANCE_PAPER_PREPARED_RUNTIME_')
                     or name == 'PROVENANCE_PAPER_PREPARED_RUNTIMES_JSON')
            if not owned:
                retained.append(line)
        compact = json.dumps(catalogs, separators=(',', ':'), ensure_ascii=False)
        encoded = b''.join(retained) + ('PROVENANCE_PAPER_CATALOGS_JSON=' + json.dumps(compact, ensure_ascii=False) + '\n').encode()
        check(len(encoded) <= MAX_CATALOG*2, 'Catalog environment exceeds limit')
        return encoded

    def assets(self, revision):
        assets = {}
        for catalog in revision['catalogs']:
            for asset in (catalog['paper']['artifact'], catalog['java']['artifact'], catalog['probe'], catalog['preparedRuntime']['artifact']):
                prior = assets.get(asset['sha256'])
                check(prior is None or prior == asset, 'Catalog digest has conflicting identities')
                assets[asset['sha256']] = asset
        return assets

    def populate_cache(self, staged):
        uid = run('id', '-u', USER).decode().strip()
        check(re.fullmatch(r'[1-9][0-9]*', uid), 'Invalid worker account identity')
        for digest, source in staged.items():
            target = STATE/'cache'/'content'/'sha256'/digest[:2]/digest[2:]
            run('runuser', '-u', USER, '--', 'mkdir', '-p', str(target.parent))
            with source.open('rb') as content:
                result = subprocess.run(['runuser', '-u', USER, '--', 'python3', '-I', '-c',
                    'import os,sys,tempfile,shutil; p=sys.argv[1]; fd,t=tempfile.mkstemp(dir=os.path.dirname(p)); '
                    'f=os.fdopen(fd,"wb"); shutil.copyfileobj(sys.stdin.buffer,f); f.flush(); os.fsync(f.fileno()); '
                    'f.close(); os.chmod(t,0o444); os.replace(t,p)', str(target)], stdin=content,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300)
            check(result.returncode == 0, 'Unable to populate worker catalog cache')

    def switch(self, operation, catalogs):
        protected(ROOT/'settings.json')
        protected(ROOT/'runner.env')
        settings = decode(read(ROOT/'settings.json', MAX_CATALOG*2))
        settings.pop('probe', None)
        settings.pop('preparedRuntime', None)
        settings['paperCatalogs'] = catalogs
        environment = self.catalog_environment(read(ROOT/'runner.env', MAX_CATALOG*2), catalogs)
        atomic(ROOT/'runner.env', environment, 0o640)
        gid = int(run('id', '-g', USER).decode().strip())
        check(gid > 0, 'Invalid worker group identity')
        os.chown(ROOT/'runner.env', 0, gid)
        # runner.env is the runtime authority and is always replaced as one
        # complete file. settings.json follows as operator-readable inventory.
        atomic(ROOT/'settings.json', (json.dumps(settings)+'\n').encode())
        metadata = decode(read(ROOT/'installed.json'))
        metadata['catalogSha256'] = operation['revision']['sha256']
        atomic(ROOT/'installed.json', json.dumps(metadata).encode())

    def restore(self, operation):
        backup = WORK/operation['backup']
        protected(backup/'settings.json')
        protected(backup/'runner.env')
        protected(backup/'installed.json')
        atomic(ROOT/'settings.json', read(backup/'settings.json', MAX_CATALOG*2))
        atomic(ROOT/'runner.env', read(backup/'runner.env', MAX_CATALOG*2), 0o640)
        gid = int(run('id', '-g', USER).decode().strip())
        check(gid > 0, 'Invalid worker group identity')
        os.chown(ROOT/'runner.env', 0, gid)
        atomic(ROOT/'installed.json', read(backup/'installed.json'))

    def rollback(self, operation):
        operation['phase'] = 'rollback'
        self.save(operation)
        no_scopes()
        service('stop')
        if not local_quiet():
            service('start')
            return
        no_scopes()
        self.restore(operation)
        service('start')
        self.finish(operation, 'rolled_back' if self.healthy(operation, 'rollback-health') else 'failed')

    def step(self):
        if self.journal.exists():
            operation = decode(read(self.journal, MAX_CATALOG*2))
            if operation['phase'] == 'committing':
                self.finish(operation, operation['report'])
                return
            if operation['phase'] != 'complete':
                result = self.client.catalog_poll(operation['id'])
                if result['phase'] == 'complete':
                    check(result['outcome'] in ('succeeded', 'rolled_back', 'failed'), 'Unexpected terminal catalog outcome')
                    operation['phase'] = 'complete'; self.save(operation)
                    return
                self.rollback(operation)
                return
        command = self.client.catalog_poll()
        if command['phase'] != 'install': return
        try:
            revision = command['revision']
            verify_catalog(revision, self.config['releasePublicKey'])
            if not local_quiet(): return
            no_scopes()
            with tempfile.TemporaryDirectory(dir=WORK) as temporary:
                catalog_file = Path(temporary)/'catalogs.json'
                catalog_file.write_text(json.dumps(revision['catalogs'], separators=(',', ':'), ensure_ascii=False))
                run(str(ROOT/'runner'), 'validate-paper-catalogs', str(catalog_file))
            staged = {}
            assets = self.assets(revision)
            installed_settings = decode(read(ROOT/'settings.json', MAX_CATALOG*2))
            disk_budget = installed_settings.get('resources', {}).get('diskBytes')
            check(type(disk_budget) is int and 0 < sum(asset['sizeBytes'] for asset in assets.values()) <= disk_budget,
                  'Catalog assets exceed node disk budget')
            asset_root = WORK/'catalog-assets'
            if not asset_root.exists(): asset_root.mkdir(mode=0o700)
            check(asset_root.resolve() == asset_root and asset_root.stat().st_uid == 0 and stat.S_IMODE(asset_root.stat().st_mode) == 0o700, 'Unsafe catalog asset directory')
            for digest, asset in assets.items():
                target = asset_root/digest
                if not target.exists():
                    with tempfile.TemporaryDirectory(dir=WORK) as temporary:
                        downloaded = Path(temporary)/'asset'
                        self.client.download_catalog_asset(asset, downloaded)
                        atomic(target, downloaded.read_bytes(), 0o400)
                check(sha(target) == digest and target.stat().st_size == asset['sizeBytes'], 'Staged catalog asset drift')
                staged[digest] = target
            self.populate_cache(staged)
            protected(ROOT/'runner')
            check(decode(read(ROOT/'installed.json'))['runnerSha256'] == sha(ROOT/'runner'), 'Installed runner identity drift')
            backup_name = 'catalog-backup-'+command['operationId']
            backup = WORK/backup_name
            if not backup.exists(): backup.mkdir(mode=0o700)
            check(backup.resolve() == backup and backup.stat().st_uid == 0 and stat.S_IMODE(backup.stat().st_mode) == 0o700, 'Unsafe catalog backup directory')
            for name in ('settings.json', 'runner.env', 'installed.json'):
                source = ROOT/name
                protected(source)
                if not (backup/name).exists(): atomic(backup/name, read(source, MAX_CATALOG*2))
            operation = {'id': command['operationId'], 'revision': revision, 'backup': backup_name, 'phase': 'staged'}
            self.save(operation)
        except (ValueError, TypeError, KeyError, OSError):
            self.client.catalog_poll(command['operationId'], 'failed')
            return
        try:
            service('stop')
            check(local_quiet(), 'Pending terminal replay prevents catalog activation')
            no_scopes()
            self.switch(operation, revision['catalogs'])
            operation['phase'] = 'verifying'; self.save(operation)
            service('start')
            self.finish(operation, 'succeeded') if self.healthy(operation, 'verifying') else self.rollback(operation)
        except Exception:
            current = decode(read(self.journal, MAX_CATALOG*2))
            if current['phase'] not in ('committing', 'complete'): self.rollback(current)
            else: raise


def main():
    check(os.geteuid() == 0, 'Updater requires its root service')
    os.umask(0o077)
    config = decode(read(ROOT/'updater.json'))
    check(set(config) == {'apiOrigin', 'runnerId', 'credentialFile', 'releasePublicKey'}, 'Invalid updater settings')
    u = urlsplit(config['apiOrigin'])
    check(u.scheme == 'https' and u.hostname and not u.path and not u.query and not u.fragment and not u.username, 'Invalid updater API origin')
    check(str(uuid.UUID(config['runnerId'])) == config['runnerId'], 'Invalid hosted runner identity')
    check(Path(config['credentialFile']) == ROOT/'updater-credential', 'Updater credential path is fixed')
    check(len(base64.b64decode(config['releasePublicKey'], validate=True)) == 32, 'Invalid pinned release verification key')
    if not WORK.exists():
        WORK.mkdir(mode=0o700)
    check(WORK.resolve() == WORK and WORK.stat().st_uid == 0 and stat.S_IMODE(WORK.stat().st_mode) == 0o700, 'Unsafe updater state directory')
    import fcntl
    lock = os.open(WORK/'lock', os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    updater = Updater(config, Client(config))
    catalogs = CatalogReconciler(config, updater.client)
    while True:
        try:
            updater.step()
            # Binary replacement has priority; catalogs reconcile only when its
            # crash journal is terminal and no binary operation is actionable.
            catalogs.step()
        except Exception as error:
            # Exceptions from network libraries can carry URLs/headers; log only type.
            print('Hosted update deferred: '+type(error).__name__, flush=True)
        time.sleep(10)


if __name__ == '__main__':
    main()
