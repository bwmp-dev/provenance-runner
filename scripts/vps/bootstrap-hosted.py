#!/usr/bin/env python3
"""Install a platform-owned runner from the console's private download. Python 3 stdlib only."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from urllib.parse import urlsplit
import uuid

FILES = {'runner', 'runsc', 'rootfs.tar', 'install.sh', 'install.py',
         'prepare-gvisor-rootfs.sh', 'settings.example.json', 'SOURCE_COMMIT',
         'updater.py', 'sign-release.py', 'SHA256SUMS'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate manifest field')
        result[key] = value
    return result


def validate(data):
    require(isinstance(data, dict) and set(data) == {
        'schemaVersion', 'runnerId', 'credential', 'updaterCredential', 'profile'}, 'Invalid manifest fields')
    require(data['schemaVersion'] == 'provenance.hosted-install/v1', 'Unsupported manifest version')
    require(str(uuid.UUID(data['runnerId'])) == data['runnerId'], 'Invalid runner ID')
    token = data['credential']
    require(isinstance(token, str) and re.fullmatch(r'phc_v1_[A-Za-z0-9_-]{43}', token), 'Invalid hosted credential')
    raw = base64.urlsafe_b64decode(token[7:]+'=')
    require(base64.urlsafe_b64encode(raw).decode().rstrip('=') == token[7:], 'Noncanonical credential')
    require(re.fullmatch(r'pru_[a-f0-9]{64}', data['updaterCredential']), 'Invalid updater credential')
    profile = data['profile']
    require(isinstance(profile, dict) and set(profile) == {
        'gatewayAddress', 'apiOrigin', 'artifactHosts', 'probe', 'preparedRuntime',
        'bundle', 'resources', 'releasePublicKey'}, 'Invalid installation profile')
    bundle = profile['bundle']
    require(isinstance(bundle, dict) and set(bundle) == {'uri', 'sha256', 'sizeBytes'}, 'Invalid bundle descriptor')
    require(re.fullmatch(r'[a-f0-9]{64}', bundle['sha256']), 'Invalid bundle digest')
    require(type(bundle['sizeBytes']) is int and 0 < bundle['sizeBytes'] <= 512*1024**2, 'Invalid bundle size')
    url = urlsplit(bundle['uri'])
    require(url.scheme == 'https' and url.hostname in profile['artifactHosts'] and url.port in (None, 443)
            and not url.username and not url.password and not url.fragment, 'Invalid bundle URL')
    require(len(base64.b64decode(profile['releasePublicKey'], validate=True)) == 32, 'Invalid release key')
    return data


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Bundle redirects are refused')


def download(asset, target):
    digest = hashlib.sha256()
    total = 0
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(asset['uri'], timeout=60) as response, target.open('xb') as out:
        require(response.status == 200, 'Bundle download failed')
        while block := response.read(min(1024**2, asset['sizeBytes'] - total + 1)):
            total += len(block)
            require(total <= asset['sizeBytes'], 'Bundle exceeds expected size')
            digest.update(block)
            out.write(block)
    require(total == asset['sizeBytes'] and digest.hexdigest() == asset['sha256'], 'Bundle integrity check failed')


def extract(archive, destination):
    seen = set()
    total = 0
    with tarfile.open(archive, 'r:gz') as bundle:
        for member in bundle:
            name = member.name.removeprefix('./').removeprefix('runner-bundle/')
            if member.isdir() and member.name in ('.', './', 'runner-bundle'):
                continue
            require(name in FILES and name not in seen and member.isfile(), 'Unexpected or unsafe bundle entry')
            require(0 < member.size <= 1024**3, 'Bundle entry size invalid')
            total += member.size
            require(total <= 2*1024**3, 'Expanded bundle exceeds limit')
            seen.add(name)
            with bundle.extractfile(member) as source, (destination/name).open('xb') as output:
                remaining = member.size
                while remaining:
                    block = source.read(min(1024**2, remaining))
                    require(block, 'Truncated bundle')
                    output.write(block)
                    remaining -= len(block)
            (destination/name).chmod(0o700 if name in {'runner', 'runsc', 'install.sh', 'prepare-gvisor-rootfs.sh'} else 0o600)
    require(seen == FILES, 'Incomplete bundle')


def private(path, content):
    with path.open('x', encoding='utf-8') as output:
        output.write(content+'\n')
    path.chmod(0o600)


def main():
    require(os.geteuid() == 0, 'Run with sudo on the runner VPS')
    require(len(sys.argv) == 2, 'Usage: sudo python3 install-hosted-runner.py hosted-runner.json')
    os.umask(0o077)
    # Copy bounded input through one descriptor before using it; the source may be user-owned.
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'Manifest must be a regular file')
        raw = source.read(65537)
    require(len(raw) <= 65536, 'Manifest exceeds 64 KiB')
    data = validate(json.loads(raw, object_pairs_hook=unique))
    for path in ('/opt/provenance-runner', '/var/lib/provenance-runner'):
        require(not os.path.lexists(path), 'An installation exists; refusing overwrite. Use console updates for installed nodes.')
    root = Path('/root')
    require(root.resolve() == root and root.stat().st_uid == 0 and not root.stat().st_mode & 0o022, 'Unsafe root staging directory')
    stage = Path(tempfile.mkdtemp(prefix='provenance-hosted-', dir=root))
    print('Preparing verified installation in '+str(stage), flush=True)
    profile = data['profile']
    download(profile['bundle'], stage/'bundle.tar.gz')
    bundle = stage/'runner-bundle'
    bundle.mkdir(mode=0o700)
    extract(stage/'bundle.tar.gz', bundle)
    private(stage/'credential', data['credential'])
    private(stage/'updater-credential', data['updaterCredential'])
    settings = {k: profile[k] for k in ('gatewayAddress', 'artifactHosts', 'probe', 'preparedRuntime', 'resources')}
    settings.update(runnerId=data['runnerId'], platformCredentialFile=str(stage/'credential'))
    private(stage/'settings.json', json.dumps(settings))
    private(stage/'updater.json', json.dumps({'apiOrigin': profile['apiOrigin'], 'credentialFile': str(stage/'updater-credential'), 'releasePublicKey': profile['releasePublicKey']}))
    subprocess.run(['bash', str(bundle/'install.sh'), 'install', str(stage/'settings.json')], check=True)
    subprocess.run(['bash', str(bundle/'install.sh'), 'enable-updater', str(stage/'updater.json')], check=True)
    for name in ('credential', 'updater-credential', 'settings.json', 'updater.json'):
        (stage/name).unlink()
    print('Runner and updater installed. Check the node in Administration → Hosted runners. Delete your downloaded manifest after confirming it is online.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError):
        # Network exceptions can embed presigned URLs. Never print exception text.
        print('Hosted installation failed. No existing installation was overwritten. Root staging files are retained for diagnosis; do not share credentials or download URLs.', file=sys.stderr)
        sys.exit(1)
