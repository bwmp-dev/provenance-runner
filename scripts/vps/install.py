#!/usr/bin/env python3
"""Platform-hosted Ubuntu 24.04/26.04 LTS amd64 runner installation; never upgrades existing state."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time
import tempfile
import uuid
from urllib.parse import urlsplit, parse_qsl

ROOT = Path('/opt/provenance-runner')
STATE = Path('/var/lib/provenance-runner')
USER = 'provenance-worker'
UNIT = 'provenance-runner.service'
TREE = '55b3d6002a16c74e9f37638a451a4b4c32b4078b06377d85a8633b89c2506500'
RUNSC = '456ea862b62b48bb7ff27ae38c262b52315bf3d68ea0733164e4817cadc518a1'
PROBE = '040062e4ea15fdffe3c37e4402b978527dd4864870edefe2c662209e12d63868'
LEGACY_PROBE = ('0.2.0', '18400bb4a47d28c1d95c3f4067603af3f3409d5e',
                '141a535d495a3afd5f413cab04618e75421390f0e14acba0707d1573c5a8c96b', 480768)
FILES = {'runner', 'runsc', 'rootfs.tar', 'install.sh', 'install.py',
         'prepare-gvisor-rootfs.sh', 'settings.example.json', 'SOURCE_COMMIT', 'updater.py', 'sign-release.py', 'sign-catalog.py'}
SYSTEM_UNIT = Path('/etc/systemd/system') / UNIT
USER_UNIT = Path('/etc/systemd/user') / UNIT
PROFILE = Path('/etc/apparmor.d/opt.provenance-runner.runsc')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def run(*args, capture=False):
    # Never echo arguments or worker stderr: they may contain private state.
    result = subprocess.run(args, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True)
    require(result.returncode == 0, f'{Path(args[0]).name} failed (exit {result.returncode}); installation retained')
    return result.stdout.strip() if capture else ''


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def protected(path, private=False):
    require(path.is_absolute() and path.resolve() == path, 'Input must have a canonical absolute path without symlinks')
    for parent in path.parents:
        s = parent.stat()
        require(s.st_uid == 0 and not s.st_mode & 0o022, 'Input parent must be root-owned and not group/world writable')
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1
            and not s.st_mode & 0o7022, 'Input must be a root-owned regular single-link file without special/write bits')
    if private:
        require(stat.S_IMODE(s.st_mode) in (0o400, 0o600), 'Private input must have mode 0400 or 0600')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field')
        result[key] = value
    return result


def read_json(path):
    require(path.stat().st_size <= 262144, 'JSON input exceeds 256 KiB')
    return json.loads(path.read_text(), object_pairs_hook=unique)


def exact(obj, keys):
    require(isinstance(obj, dict) and set(obj) == set(keys.split()), 'Missing or unsupported settings fields')


def number(value, maximum):
    require(type(value) is int and 0 < value <= maximum, 'Resource or artifact bound is invalid')


def host(value):
    require(isinstance(value, str) and len(value) <= 253 and re.fullmatch(r'[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?', value), 'Use a lowercase DNS hostname')
    require(all(label and len(label) <= 63 and not label.startswith('-') and not label.endswith('-') for label in value.split('.')), 'Invalid DNS hostname')


def https(value, origin=False):
    require(isinstance(value, str) and not any(c.isspace() for c in value), 'Invalid HTTPS URL')
    parsed = urlsplit(value)
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username
            and not parsed.password and not parsed.fragment
            and not any(c in value for c in '\"\\\'`$'), 'Use HTTPS without credentials or fragment')
    if parsed.query:
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        query = dict(pairs)
        allowed = {'X-Amz-Algorithm', 'X-Amz-Credential', 'X-Amz-Date', 'X-Amz-Expires', 'X-Amz-SignedHeaders', 'X-Amz-Signature', 'X-Amz-Security-Token', 'x-id', 'X-Amz-Checksum-Mode'}
        required = {'X-Amz-Algorithm', 'X-Amz-Credential', 'X-Amz-Date', 'X-Amz-Expires', 'X-Amz-SignedHeaders', 'X-Amz-Signature'}
        require(not origin and len(parsed.query) <= 8192 and len(pairs) == len(query)
                and required <= set(query) <= allowed and query['X-Amz-Algorithm'] == 'AWS4-HMAC-SHA256'
                and query['X-Amz-Expires'].isdigit() and 0 < int(query['X-Amz-Expires']) <= 86400,
                'Only bounded S3 signed asset downloads may include a query')
    host(parsed.hostname)
    require(parsed.port in (None, 443), 'HTTPS endpoints must use port 443')
    if origin:
        require(not parsed.path, 'API origin must not include a path')
    return parsed


def validate(settings):
    catalog_mode = 'paperCatalogs' in settings
    exact(settings, 'gatewayAddress runnerId artifactHosts resources platformCredentialFile ' +
          ('paperCatalogs' if catalog_mode else 'probe preparedRuntime'))
    address = settings['gatewayAddress'].split(':')
    require(len(address) == 2 and address[1].isdigit() and 0 < int(address[1]) < 65536, 'gatewayAddress must be DNS:port')
    host(address[0])
    require(str(uuid.UUID(settings['runnerId'])) == settings['runnerId'], 'Use a canonical runner UUID')
    require(Path(settings['platformCredentialFile']).is_absolute(), 'platformCredentialFile must be absolute')
    hosts = settings['artifactHosts']
    require(isinstance(hosts, list) and 0 < len(hosts) <= 32 and len(set(hosts)) == len(hosts), 'Provide unique artifact DNS hosts')
    for name in hosts:
        host(name)
    if catalog_mode:
        validate_catalogs(settings['paperCatalogs'], hosts)
    else:
        for key in ('probe', 'preparedRuntime'):
            artifact = settings[key]
            exact(artifact, 'uri sha256 sizeBytes' + (' maximumExpandedBytes' if key == 'preparedRuntime' else ''))
            validate_asset(artifact, hosts)
        require(settings['probe']['sha256'] == PROBE and settings['probe']['sizeBytes'] == 478853, 'Probe must match the accepted catalog')
        number(settings['preparedRuntime']['maximumExpandedBytes'], 1024**3)
    exact(settings['resources'], 'cpuMillis memoryBytes diskBytes processCount')
    for key, limit in {'cpuMillis': 1024000, 'memoryBytes': 1024**4, 'diskBytes': 16*1024**4, 'processCount': 2**20}.items():
        number(settings['resources'][key], limit)
    return settings


def validate_asset(artifact, hosts):
    require(https(artifact['uri']).hostname in hosts, 'Artifact host is absent from artifactHosts')
    require(isinstance(artifact['sha256'], str) and re.fullmatch('[0-9a-f]{64}', artifact['sha256']), 'Invalid artifact SHA256')
    number(artifact['sizeBytes'], 512*1024**2)


def validate_catalogs(catalogs, hosts):
    require(isinstance(catalogs, list) and 0 < len(catalogs) <= 32, 'Provide 1 to 32 Paper catalogs')
    identities, remote, runtime_digests = set(), set(), set()
    for catalog in catalogs:
        exact(catalog, 'environmentId paper java probeVersion probeSourceCommit probe preparedRuntime')
        identity = catalog['environmentId']
        require(isinstance(identity, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.+-]{0,199}', identity)
                and identity not in identities, 'Invalid or duplicate environment ID')
        identities.add(identity)
        paper, java, runtime = catalog['paper'], catalog['java'], catalog['preparedRuntime']
        exact(paper, 'gameVersion build artifact')
        require(isinstance(paper['gameVersion'], str) and re.fullmatch(r'(?:1\.(?:7\.10|[89](?:\.[0-9]+)?|1[0-9](?:\.[0-9]+)?|2[01](?:\.[0-9]+)?)|26\.[1-9][0-9]*(?:\.[0-9]+)?)', paper['gameVersion']), 'Invalid Paper release version')
        number(paper['build'], 2**32-1)
        exact(java, 'distribution version os architecture archiveRoot artifact maximumExpandedBytes')
        require(java['distribution'] == 'eclipse-temurin' and java['os'] == 'linux' and java['architecture'] == 'amd64', 'Java must be Temurin for Linux amd64')
        for key in ('distribution', 'version', 'archiveRoot'):
            require(isinstance(java[key], str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.+-]{0,199}', java[key]), 'Invalid Java identity or archive root')
        require(re.fullmatch(r'(?:8|11|16|17|21|25)\.[0-9]+\.[0-9]+(?:\.[0-9]+)?\+[0-9]+', java['version']), 'Java version must be an exact numeric release')
        exact(runtime, 'artifact maximumExpandedBytes')
        for archive in (java, runtime):
            number(archive['maximumExpandedBytes'], 1024**3)
            require(archive['maximumExpandedBytes'] >= archive['artifact']['sizeBytes'], 'Expanded archive bound is too small')
        for artifact in (paper['artifact'], java['artifact'], catalog['probe'], runtime['artifact']):
            exact(artifact, 'uri sha256 filename sizeBytes')
            validate_asset(artifact, hosts)
            require(isinstance(artifact['filename'], str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.+-]{0,199}', artifact['filename']), 'Invalid artifact filename')
        probe_identity = (catalog['probeVersion'], catalog['probeSourceCommit'], catalog['probe']['sha256'], catalog['probe']['sizeBytes'])
        original = ('0.1.0', 'f82dcbf8244354059731ba533f73909ed5528bbd', PROBE, 478853)
        require(probe_identity in (original, LEGACY_PROBE), 'Probe must match an accepted immutable catalog')
        if probe_identity == original:
            require(re.fullmatch(r'(?:1\.20\.(?:[6-9]|[1-9][0-9]+)|1\.21(?:\.[0-9]+)?|26\.[1-9][0-9]*(?:\.[0-9]+)?)', paper['gameVersion']), 'Original probe cannot run legacy Paper')
        key = (paper['gameVersion'], paper['build'], java['distribution'], java['version'], paper['artifact']['sha256'])
        require(key not in remote and runtime['artifact']['sha256'] not in runtime_digests, 'Duplicate runtime identity')
        remote.add(key)
        runtime_digests.add(runtime['artifact']['sha256'])


def assets_for_settings(settings):
    if 'paperCatalogs' not in settings:
        return [(name, settings[name]) for name in ('probe', 'preparedRuntime')]
    assets = {}
    for catalog in settings['paperCatalogs']:
        for asset in (catalog['paper']['artifact'], catalog['java']['artifact'], catalog['probe'], catalog['preparedRuntime']['artifact']):
            previous = assets.get(asset['sha256'])
            require(previous is None or previous['sizeBytes'] == asset['sizeBytes'], 'Conflicting asset sizes')
            assets[asset['sha256']] = asset
    return list(assets.items())


def archive_check(path):
    # Inspect every name before extracting even this checksum-pinned operator image.
    with tarfile.open(path) as archive:
        entries = archive.getmembers()
        require(len(entries) < 100000 and sum(m.size for m in entries) < 4*1024**3, 'Rootfs archive exceeds bounds')
        links = set()
        names = {}
        for m in entries:
            p = PurePosixPath(m.name)
            require(not p.is_absolute() and '..' not in p.parts, 'Rootfs archive path traversal')
            require(m.isdir() or m.isfile() or m.issym() or m.islnk(), 'Rootfs archive has a special device')
            require(str(p) not in names, 'Duplicate rootfs member')
            names[str(p)] = m
            if m.issym():
                links.add(p)
        for m in entries:
            require(not any(p in links for p in PurePosixPath(m.name).parents), 'Rootfs archive writes through a symlink')
            if m.islnk():
                target = PurePosixPath(m.linkname)
                require(not target.is_absolute() and '..' not in target.parts
                        and str(target) in names and names[str(target)].isfile(), 'Unsafe rootfs hardlink')


def directory(path, mode):
    path.mkdir(mode=mode)
    path.chmod(mode)


def write(path, text, mode=0o600, owner=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), mode)
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    if owner:
        os.chown(path, owner.pw_uid, owner.pw_gid)


def as_user(account, *args, capture=False):
    return run('runuser', '-u', USER, '--', 'env', '-i',
               'PATH=/usr/bin:/bin', f'HOME={STATE}/home',
               f'XDG_RUNTIME_DIR=/run/user/{account.pw_uid}',
               f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus',
               *args, capture=capture)


def verify_bundle(bundle):
    protected(bundle/'SHA256SUMS')
    records = {}
    for line in (bundle/'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9_.-]+)', line)
        require(match and match[2] not in records, 'Invalid bundle checksum manifest')
        records[match[2]] = match[1]
    require(set(records) == FILES, 'Bundle inventory mismatch')
    for name, expected in records.items():
        protected(bundle/name)
        require(digest(bundle/name) == expected, 'Bundle checksum mismatch: '+name)
    require(records['runsc'] == RUNSC, 'gVisor is not the accepted pinned build')
    require(re.fullmatch('[0-9a-f]{40}\n', (bundle/'SOURCE_COMMIT').read_text()), 'Invalid source commit')
    with (bundle/'runner').open('rb') as executable:
        header = executable.read(20)
    require(header[:5] == b'\x7fELF\x02' and header[5] == 1 and header[18:20] == b'\x3e\x00', 'Runner must be an amd64 ELF binary')
    archive_check(bundle/'rootfs.tar')


def environment(settings, account):
    env = {
        'PROVENANCE_RUNSC_PATH': str(ROOT/'runsc-rootless'),
        'PROVENANCE_ROOTFS': str(ROOT/'rootfs'),
        'PROVENANCE_ROOTFS_IDENTITY': 'sha256:'+TREE,
        'PROVENANCE_GVISOR_CGROUP_DRIVER': 'systemd-user',
        'PROVENANCE_SYSTEMD_CGROUP_ROOT': f'/sys/fs/cgroup/user.slice/user-{account.pw_uid}.slice/user@{account.pw_uid}.service/app.slice',
        'PROVENANCE_ARTIFACT_HOSTS': ','.join(settings['artifactHosts']),
    }
    for key, name in {'WORKSPACE_ROOT': 'workspaces', 'CACHE_ROOT': 'cache', 'GVISOR_STATE_ROOT': 'gvisor-state', 'GVISOR_BUNDLE_ROOT': 'bundles'}.items():
        env['PROVENANCE_'+key] = str(STATE/name)
    if 'paperCatalogs' in settings:
        env['PROVENANCE_PAPER_CATALOGS_JSON'] = json.dumps(settings['paperCatalogs'], separators=(',', ':'))
    else:
        for key, prefix in [('probe', 'PROVENANCE_PAPER_PROBE'), ('preparedRuntime', 'PROVENANCE_PAPER_PREPARED_RUNTIME')]:
            for field, suffix in [('uri', 'URI'), ('sha256', 'SHA256'), ('sizeBytes', 'SIZE_BYTES')]:
                env[prefix+'_'+suffix] = str(settings[key][field])
        env['PROVENANCE_PAPER_PREPARED_RUNTIME_MAX_EXPANDED_BYTES'] = str(settings['preparedRuntime']['maximumExpandedBytes'])
    # Values were strictly validated; quote for systemd, never source as shell.
    return ''.join(k+'='+json.dumps(v)+'\n' for k, v in sorted(env.items()))


def connection_credential(value):
    value = value.strip()
    require(re.fullmatch(r'phc_v1_[A-Za-z0-9_-]{43}', value), 'Expected a platform-hosted connection credential')
    raw = base64.urlsafe_b64decode(value[7:]+'=')
    require(base64.urlsafe_b64encode(raw).decode().rstrip('=') == value[7:], 'Noncanonical connection credential')
    return value


def supported_host_os():
    # Use the standard os-release parser: valid values may be quoted or unquoted.
    release = platform.freedesktop_os_release()
    require(release.get('ID') == 'ubuntu' and release.get('VERSION_ID') in ('24.04', '26.04'),
            'Supported hosts: Ubuntu 24.04 or 26.04 LTS')


def host_preflight(settings):
    require(platform.machine() == 'x86_64' and Path('/run/systemd/system').is_dir(), 'Requires amd64 VPS booted with systemd')
    supported_host_os()
    require(Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'cgroup v2 is required')
    for path in (ROOT, STATE, SYSTEM_UNIT, USER_UNIT, PROFILE):
        for parent in path.parents:
            require(parent.resolve() == parent and parent.is_dir() and parent.stat().st_uid == 0
                    and not parent.stat().st_mode & 0o022, 'Installation parent must be protected: '+str(parent))
        require(not path.exists() and not path.is_symlink(), 'Existing installation or foreign path; refusing overwrite: '+str(path))
    try:
        pwd.getpwnam(USER)
    except KeyError:
        pass
    else:
        raise ValueError('Service account already exists; fresh install only')
    require(settings['resources']['cpuMillis'] <= (os.cpu_count() or 1)*1000, 'Advertised CPU exceeds host capacity')
    memory = int(re.search(r'MemTotal:\s+(\d+)', Path('/proc/meminfo').read_text())[1])*1024
    require(settings['resources']['memoryBytes'] <= memory, 'Advertised memory exceeds host capacity')
    require(settings['resources']['diskBytes'] + 4*1024**3 <= shutil.disk_usage('/var/lib').free, 'Insufficient disk for advertised capacity and runtime')
    require(Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y', 'AppArmor must be enabled; no global sysctl changes are made')


def install(bundle, settings_path, prepare_only):
    protected(settings_path, private=True)
    settings = validate(read_json(settings_path))
    verify_bundle(bundle)
    credential_path = Path(settings['platformCredentialFile'])
    protected(credential_path, private=True)
    require(0 < credential_path.stat().st_size <= 4096, 'Runner credential size is invalid')
    credential = connection_credential(credential_path.read_text(encoding='utf-8'))
    host_preflight(settings)
    print('Installing host packages and isolated service account...', flush=True)
    run('apt-get', 'update')
    run('apt-get', 'install', '-y', '--no-install-recommends', 'ca-certificates', 'curl', 'apparmor', 'apparmor-utils', 'dbus-user-session', 'systemd-container', 'uidmap')
    print('Checking published Paper assets against their hashes...', flush=True)
    assets = tempfile.TemporaryDirectory(prefix='provenance-assets-', dir='/root')
    temporary = assets.name
    for name, artifact in assets_for_settings(settings):
        target = Path(temporary)/name
        run('curl', '--fail', '--location', '--silent', '--show-error', '--proto', '=https',
            '--proto-redir', '=https', '--max-time', '300', '--max-filesize', str(artifact['sizeBytes']),
            '--output', str(target), artifact['uri'])
        require(target.stat().st_size == artifact['sizeBytes'] and digest(target) == artifact['sha256'],
                'Published artifact bytes do not match pin: '+name)
    directory(ROOT, 0o755)
    directory(STATE, 0o711)
    write(ROOT/'INSTALLING', 'Incomplete installation: retain and inspect; do not automatically overwrite.\n')
    run('useradd', '--system', '--user-group', '--home-dir', str(STATE/'home'), '--shell', '/usr/sbin/nologin', USER)
    account = pwd.getpwnam(USER)
    for name in ('home', 'config', 'workspaces', 'cache', 'gvisor-state', 'bundles'):
        p = STATE/name
        p.mkdir(mode=0o700)
        os.chown(p, account.pw_uid, account.pw_gid)
    # Keep verified pins in the content cache: installation URLs expire after 24h.
    # The cache rechecks hashes on reads and does not evict entries automatically.
    for name, artifact in assets_for_settings(settings):
        sha = artifact['sha256']
        parent = STATE/'cache'/'content'/'sha256'/sha[:2]
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for cache_directory in (STATE/'cache'/'content', STATE/'cache'/'content'/'sha256', parent):
            os.chown(cache_directory, account.pw_uid, account.pw_gid)
            cache_directory.chmod(0o700)
        target = parent/sha[2:]
        shutil.copyfile(Path(temporary)/name, target)
        os.chown(target, account.pw_uid, account.pw_gid)
        target.chmod(0o444)
    assets.cleanup()
    for name in ('runner', 'runsc', 'prepare-gvisor-rootfs.sh'):
        shutil.copyfile(bundle/name, ROOT/name)
        os.chmod(ROOT/name, 0o755)
    write(ROOT/'settings.json', json.dumps(settings)+'\n')
    write(ROOT/'runner.env', environment(settings, account), 0o640)
    os.chown(ROOT/'runner.env', 0, account.pw_gid)
    write(ROOT/'runsc-rootless', '#!/bin/sh\nexec /opt/provenance-runner/runsc --rootless=true --gofer-network-namespace=new "$@"\n', 0o755)
    write(PROFILE, 'abi <abi/4.0>,\ninclude <tunables/global>\n/opt/provenance-runner/runsc flags=(default_allow) {\n  userns,\n}\n', 0o644)
    run('apparmor_parser', '-r', str(PROFILE))
    rootfs = ROOT/'rootfs'
    rootfs.mkdir(mode=0o700)
    run('tar', '--extract', '--file', str(bundle/'rootfs.tar'), '--directory', str(rootfs), '--no-same-owner')
    # Guest mount targets must belong to the runtime UID. The backing tree is
    # hidden by a read-only mount; its parent and service executable stay root-owned.
    run('chown', '-hR', f'{account.pw_uid}:{account.pw_gid}', str(rootfs))
    actual = run(str(ROOT/'prepare-gvisor-rootfs.sh'), 'prepare', str(rootfs), capture=True)
    require(actual == TREE, 'Prepared rootfs tree differs from the accepted pin; activation refused')
    write(ROOT/'verify-rootfs', '#!/bin/sh\nset -eu\nactual=$(/opt/provenance-runner/prepare-gvisor-rootfs.sh prepare /opt/provenance-runner/rootfs)\n[ "$actual" = "'+TREE+'" ]\n', 0o755)
    connect = {'schemaVersion': 'provenance.runner-connect/v1alpha1', 'gatewayAddress': settings['gatewayAddress'],
               'runnerId': settings['runnerId'], 'instanceId': 'vps-'+str(uuid.uuid4()),
               'credentialFile': 'credential', 'expectedScope': {'kind': 'platform'},
               'resources': settings['resources']}
    write(STATE/'config/connect.json', json.dumps(connect)+'\n', owner=account)
    write(STATE/'config/credential', credential, owner=account)
    write(USER_UNIT, '''[Unit]
Description=Provenance sandboxed runner
[Service]
Type=simple
ExecStart=/opt/provenance-runner/runner connect /var/lib/provenance-runner/config/connect.json
EnvironmentFile=/opt/provenance-runner/runner.env
Restart=on-failure
RestartSec=10
TimeoutStopSec=120
KillMode=control-group
NoNewPrivileges=yes
UMask=0077
Slice=app.slice
''', 0o644)
    # Only the system unit is enabled. It verifies/mounts the tree before starting
    # the user unit on every boot, even though the lingering manager starts early.
    write(SYSTEM_UNIT, f'''[Unit]
Description=Provenance runner lifecycle
Wants=network-online.target
Requires=user@{account.pw_uid}.service
After=network-online.target user@{account.pw_uid}.service apparmor.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/opt/provenance-runner/verify-rootfs
ExecStart=/usr/sbin/runuser -u {USER} -- /usr/bin/env XDG_RUNTIME_DIR=/run/user/{account.pw_uid} DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus /usr/bin/systemctl --user start {UNIT}
ExecStop=/usr/sbin/runuser -u {USER} -- /usr/bin/env XDG_RUNTIME_DIR=/run/user/{account.pw_uid} DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus /usr/bin/systemctl --user stop {UNIT}
TimeoutStartSec=120
TimeoutStopSec=150
[Install]
WantedBy=multi-user.target
''', 0o644)
    run('loginctl', 'enable-linger', USER)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', f'user@{account.pw_uid}.service')
    as_user(account, 'systemctl', '--user', 'daemon-reload')
    write(ROOT/'installed.json', json.dumps({'sourceCommit': (bundle/'SOURCE_COMMIT').read_text().strip(),
          'runnerSha256': digest(ROOT/'runner'), 'runscSha256': RUNSC, 'rootfsTreeSha256': TREE})+'\n')
    (ROOT/'INSTALLING').unlink()
    print('Installed. Rootfs verified; runner is inactive.', flush=True)
    if not prepare_only:
        activate()


def activate():
    protected(ROOT/'installed.json')
    require(not (ROOT/'INSTALLING').exists(), 'Incomplete installation requires inspection')
    protected(ROOT/'settings.json', private=True)
    settings = validate(read_json(ROOT/'settings.json'))
    installed = read_json(ROOT/'installed.json')
    for name, key in [('runner', 'runnerSha256'), ('runsc', 'runscSha256')]:
        protected(ROOT/name)
        require(digest(ROOT/name) == installed[key], 'Installed executable drift; refusing activation')
    account = pwd.getpwnam(USER)
    # Verify gateway trust before starting the platform worker.
    address, port = settings['gatewayAddress'].split(':')
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2'])
    with socket.create_connection((address, int(port)), timeout=15) as sock:
        with context.wrap_socket(sock, server_hostname=address) as tls:
            require(tls.selected_alpn_protocol() == 'h2', 'Gateway must negotiate trusted TLS with HTTP/2')
    require((STATE/'config/credential').is_file(), 'Installed platform runner credential is missing')
    print('Gateway TLS verified. Starting hosted runner...', flush=True)
    run('systemctl', 'enable', '--now', UNIT)
    time.sleep(3)
    status = as_user(account, 'systemctl', '--user', 'show', UNIT, '-p', 'ActiveState', '-p', 'SubState', '-p', 'NRestarts', capture=True)
    require('ActiveState=active' in status and 'SubState=running' in status and 'NRestarts=0' in status, 'Runner did not remain running; inspect the private journal')
    print('Runner service is running and enabled for boot. Confirm online status in the console; this is not a completed Paper job test.')


def configure_catalogs(catalog_path):
    """Apply verified catalogs to a drained, stopped node without replacing identity."""
    protected(catalog_path, private=True)
    protected(ROOT/'settings.json', private=True)
    protected(ROOT/'installed.json', private=True)
    require(not (ROOT/'INSTALLING').exists(), 'Incomplete installation requires inspection')
    settings = read_json(ROOT/'settings.json')
    catalogs = read_json(catalog_path)
    settings.pop('probe', None)
    settings.pop('preparedRuntime', None)
    settings['paperCatalogs'] = catalogs
    validate(settings)
    account = pwd.getpwnam(USER)
    status = as_user(account, 'systemctl', '--user', 'show', UNIT, '-p', 'ActiveState', capture=True)
    require(status.strip() == 'ActiveState=inactive', 'Drain the node and stop its user service before changing catalogs')
    protected(ROOT/'runner')
    installed = read_json(ROOT/'installed.json')
    require(digest(ROOT/'runner') == installed['runnerSha256'], 'Installed executable drift')
    # Old binaries ignore the new env variable. Require explicit support before changes.
    run(str(ROOT/'runner'), 'validate-paper-catalogs', str(catalog_path))
    assets = assets_for_settings(settings)
    require(sum(asset['sizeBytes'] for _, asset in assets) <= settings['resources']['diskBytes'], 'Catalog assets exceed node disk budget')
    # Download into a private root directory before touching installed configuration.
    with tempfile.TemporaryDirectory(prefix='provenance-catalogs-', dir='/root') as temporary:
        for name, asset in assets:
            target = Path(temporary)/name
            run('curl', '--fail', '--location', '--silent', '--show-error', '--proto', '=https',
                '--proto-redir', '=https', '--max-time', '300', '--max-filesize', str(asset['sizeBytes']),
                '--output', str(target), asset['uri'])
            require(target.stat().st_size == asset['sizeBytes'] and digest(target) == asset['sha256'], 'Catalog artifact integrity mismatch')
        # Root must not follow paths inside the worker-owned cache. Transfer using
        # the worker's uid and a pipe, so symlinks cannot grant root write authority.
        for name, asset in assets:
            target = STATE/'cache'/'content'/'sha256'/name[:2]/name[2:]
            as_user(account, 'mkdir', '-p', str(target.parent))
            with (Path(temporary)/name).open('rb') as source:
                result = subprocess.run(['runuser', '-u', USER, '--', 'python3', '-I', '-c',
                    'import os,sys,tempfile; p=sys.argv[1]; fd,t=tempfile.mkstemp(dir=os.path.dirname(p)); '
                    'f=os.fdopen(fd,"wb"); import shutil; shutil.copyfileobj(sys.stdin.buffer,f); '
                    'f.flush(); os.fsync(f.fileno()); f.close(); os.chmod(t,0o444); os.replace(t,p)', str(target)],
                    stdin=source, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            require(result.returncode == 0, 'Unable to populate worker cache')
    # A journal marker prevents activation if interrupted between the two files.
    write(ROOT/'INSTALLING', 'Catalog configuration interrupted; restore catalog backup before activation.\n')
    backup = ROOT/('catalog-backup-'+str(uuid.uuid4()))
    backup.mkdir(mode=0o700)
    for name in ('settings.json', 'runner.env'):
        protected(ROOT/name)
        shutil.copyfile(ROOT/name, backup/name)
        os.chmod(backup/name, 0o600)
    try:
        for name, content, mode in (('settings.json', json.dumps(settings)+'\n', 0o600),
                                    ('runner.env', environment(settings, account), 0o640)):
            stage = backup/(name+'.new')
            write(stage, content, mode)
            if name == 'runner.env':
                os.chown(stage, 0, account.pw_gid)
            os.replace(stage, ROOT/name)
    except Exception:
        for name in ('settings.json', 'runner.env'):
            shutil.copyfile(backup/name, ROOT/name)
        os.chmod(ROOT/'settings.json', 0o600)
        os.chmod(ROOT/'runner.env', 0o640)
        os.chown(ROOT/'runner.env', 0, account.pw_gid)
        (ROOT/'INSTALLING').unlink()
        raise
    (ROOT/'INSTALLING').unlink()
    print('Catalogs configured and cached. Runner remains stopped; run activate after checking the configuration.')


def enable_updater(bundle, settings_path):
    verify_bundle(bundle)
    protected(ROOT/'installed.json', private=True)
    require(not (ROOT/'INSTALLING').exists(), 'Runner installation is incomplete')
    protected(settings_path, private=True)
    config = read_json(settings_path)
    exact(config, 'apiOrigin credentialFile releasePublicKey')
    https(config['apiOrigin'], origin=True)
    require(len(base64.b64decode(config['releasePublicKey'], validate=True)) == 32, 'Release key must be base64 Ed25519 public bytes')
    credential_path = Path(config['credentialFile'])
    protected(credential_path, private=True)
    require(credential_path.stat().st_size <= 128, 'Updater credential is oversized')
    credential = credential_path.read_text().strip()
    require(re.fullmatch(r'pru_[a-f0-9]{64}', credential), 'Updater credential must be pru_ followed by 64 random hex digits')
    installed_settings = read_json(ROOT/'settings.json')
    unit = Path('/etc/systemd/system/provenance-runner-updater.service')
    for path in (unit, ROOT/'updater.json', ROOT/'updater.py', ROOT/'updater-credential'):
        require(not path.exists() and not path.is_symlink(), 'Updater already exists; refusing overwrite')
    run('apt-get', 'install', '-y', '--no-install-recommends', 'openssl')
    write(ROOT/'updater-credential', credential)
    config['credentialFile'] = str(ROOT/'updater-credential')
    config['runnerId'] = installed_settings['runnerId']
    write(ROOT/'updater.json', json.dumps(config)+'\n')
    shutil.copyfile(bundle/'updater.py', ROOT/'updater.py')
    os.chmod(ROOT/'updater.py', 0o700)
    write(unit, """[Unit]
Description=Provenance hosted runner binary updater
Wants=network-online.target
After=network-online.target provenance-runner.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 -I /opt/provenance-runner/updater.py
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
Restart=on-failure
RestartSec=10
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
[Install]
WantedBy=multi-user.target
""", 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'provenance-runner-updater.service')
    print('Updater installed. Register these nonsecret values in the admin console:')
    print('Runner ID: '+config['runnerId'])
    print('Credential SHA256: '+hashlib.sha256(credential.encode()).hexdigest())
    print('Release public key: '+config['releasePublicKey'])


def main():
    os.umask(0o022)  # Bootstrap starts private; service files need their explicit shared modes.
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('install')
    p.add_argument('settings', type=Path)
    p.add_argument('--prepare-only', action='store_true', help='Install without starting the worker; run activate later')
    updater = sub.add_parser('enable-updater', help='One-time hosted binary updater installation')
    updater.add_argument('settings', type=Path)
    catalogs = sub.add_parser('configure-catalogs', help='Apply pinned catalogs to a drained, stopped existing node')
    catalogs.add_argument('catalogs', type=Path)
    sub.add_parser('activate', help='Retry activation of a completed installation; preserves identity/journal')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Run as root')
    if args.action == 'install':
        install(Path(__file__).resolve().parent, args.settings.absolute(), args.prepare_only)
    elif args.action == 'configure-catalogs':
        verify_bundle(Path(__file__).resolve().parent)
        configure_catalogs(args.catalogs.absolute())
    elif args.action == 'enable-updater':
        enable_updater(Path(__file__).resolve().parent, args.settings.absolute())
    else:
        activate()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('Installation stopped: '+str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('Installation stopped due to an internal error; retain the staged files for inspection.', file=sys.stderr)
        sys.exit(1)
