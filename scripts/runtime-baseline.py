#!/usr/bin/env python3
"""Create a reviewed inactive system-service baseline. No activation or downloads.

Root and the kernel are trusted. The journal is a retained ownership ledger, not
permission to resume partial work. No recovery operation removes any object.
"""
import argparse
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit


class Refusal(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Refusal(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def parse(data):
    require(len(data) <= 65536, 'JSON size bound')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()), 'unsupported fields')


def canonical(value):
    require(type(value) is str and len(value) <= 4096 and
            re.fullmatch(r'/[A-Za-z0-9_./-]+', value), 'unsupported path')
    p = Path(value)
    require(str(p) == value and p != Path('/') and p.resolve() == p, 'noncanonical path')
    return p


def ancestry(p):
    for item in p.parents:
        s = item.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and
                not s.st_mode & 0o7022, 'unprotected ancestry')


def identity(p):
    s = p.lstat()
    return dict(device=s.st_dev, inode=s.st_ino, mode=stat.S_IMODE(s.st_mode),
                uid=s.st_uid, gid=s.st_gid, kind='directory' if stat.S_ISDIR(s.st_mode) else 'file')


def read(p, owner=0, private=False, maximum=65536, executable=False):
    p = canonical(str(p))
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == owner and
                not s.st_mode & 0o7022 and s.st_size <= maximum, 'unsafe input file')
        if private:
            require(stat.S_IMODE(s.st_mode) in (0o400, 0o600), 'private input permissions')
        data = bytearray()
        while len(data) <= maximum:
            part = os.read(fd, min(1 << 20, maximum + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        require(len(data) <= maximum, 'input size bound')
        after = os.fstat(fd)
        require((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and (p.lstat().st_dev, p.lstat().st_ino) == (s.st_dev, s.st_ino), 'input changed')
        if executable:
            require(data[:4] == b'\x7fELF' and s.st_mode & 0o111, 'direct ELF required')
        return bytes(data)
    finally:
        os.close(fd)


def pinned(pin, private=False, executable=False):
    fields(pin, 'path sha256')
    require(type(pin['sha256']) is str and re.fullmatch('[a-f0-9]{64}', pin['sha256']), 'invalid pin')
    p = canonical(pin['path'])
    ancestry(p)
    data = read(p, private=private, maximum=512 << 20 if executable else 65536,
                executable=executable)
    require(digest(data) == pin['sha256'], 'input pin mismatch')
    return data


def command(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536, 'command output bound')
    require(not check or result.returncode == 0, 'system command refused')
    return result


def manager(service):
    names = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'FragmentPath',
             'DropInPaths', 'User', 'Group', 'ExecStart', 'EnvironmentFiles',
             'Environment', 'MainPID', 'ControlPID', 'NeedDaemonReload')
    result = command('/usr/bin/systemctl', '--system', 'show', '--all', service,
                     *('--property=' + n for n in names))
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if values.get('LoadState') == 'not-found':
        # systemd omits absent array-valued service properties even with --all.
        values.setdefault('ExecStart', '')
        values.setdefault('EnvironmentFiles', '')
    require(set(values) == set(names), 'incomplete manager identity: ' + ','.join(sorted(set(names) - set(values))))
    require(values['ActiveState'] == 'inactive' and values['SubState'] == 'dead' and
            values['MainPID'] == values['ControlPID'] == '0' and not values['DropInPaths'],
            'service active or has drop-ins')
    require(values['UnitFileState'] in ('', 'disabled'), 'service not disabled')
    return values


def unit_bytes(p):
    # A deliberately narrow system-unit composition. No shell, specifiers,
    # conditionals, hooks, credential injection, extra commands or drop-ins.
    return (f'[Unit]\nDescription=Provenance inactive runner baseline\n\n'
            f'[Service]\nType=simple\nUser={p["uid"]}\nGroup={p["gid"]}\n'
            f'ExecStart={p["destination"]}/runner connect {p["stateDirectory"]}/connect.json\n'
            f'EnvironmentFile={p["destination"]}/runner.env\nRestart=no\n'
            f'NoNewPrivileges=yes\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n').encode()


ENV_NAMES = set('''PROVENANCE_RUNSC_PATH PROVENANCE_ROOTFS PROVENANCE_ROOTFS_IDENTITY
PROVENANCE_WORKSPACE_ROOT PROVENANCE_CACHE_ROOT PROVENANCE_GVISOR_STATE_ROOT
PROVENANCE_GVISOR_BUNDLE_ROOT PROVENANCE_GVISOR_CGROUP_DRIVER PROVENANCE_GVISOR_PLATFORM
PROVENANCE_SYSTEMD_RUN_PATH PROVENANCE_SYSTEMD_CGROUP_ROOT PROVENANCE_ARTIFACT_HOSTS
PROVENANCE_MAX_ARTIFACT_BYTES PROVENANCE_MAX_DEPENDENCY_BYTES PROVENANCE_MAX_PREPARATION_BYTES
PROVENANCE_MAX_CACHE_BYTES PROVENANCE_PAPER_PREPARED_RUNTIMES
PROVENANCE_PAPER_PREPARED_RUNTIME_URI PROVENANCE_PAPER_PREPARED_RUNTIME_SHA256
PROVENANCE_PAPER_PREPARED_RUNTIME_SIZE_BYTES PROVENANCE_PAPER_PREPARED_RUNTIME_MAX_EXPANDED_BYTES
PROVENANCE_PAPER_PROBE_URI PROVENANCE_PAPER_PROBE_SHA256 PROVENANCE_PAPER_PROBE_SIZE_BYTES'''.split())


def environment(data):
    require(len(data) <= 65536, 'environment bound')
    result = {}
    for line in data.decode('ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        require('=' in line, 'environment assignment required')
        name, value = line.split('=', 1)
        require(name in ENV_NAMES and name not in result, 'unsupported environment key')
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
            require("'" not in value and '\\' not in value, 'unsupported environment quoting')
        else:
            require(not any(c.isspace() or c in "'\"\\" for c in value), 'unsupported environment quoting')
        require(value and all(ord(c) >= 32 for c in value) and '$' not in value and '`' not in value,
                'unsupported environment value')
        result[name] = value
    return result


def legacy(pin):
    fields(pin, 'path treeSha256')
    root = canonical(pin['path'])
    ancestry(root)
    s = root.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o7022,
            'legacy root is not protected')
    require(re.fullmatch('[a-f0-9]{64}', pin['treeSha256']), 'invalid tree pin')
    mounts = json.loads(command('/usr/bin/findmnt', '--json', '--submounts', '--target', str(root),
                                '--output', 'TARGET,OPTIONS').stdout)['filesystems']
    require(len(mounts) == 1 and mounts[0]['target'] == str(root) and
            'ro' in mounts[0]['options'].split(',') and not mounts[0].get('children'),
            'exact read-only legacy mount required')
    # Same normalized tree identity as accepted runtime-generation.py. A private
    # bounded temporary file avoids an unbounded pipe wait on unexpected trees.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(['/usr/bin/tar', '--sort=name', '--format=gnu', '--mtime=@0',
                                 '--owner=0', '--group=0', '--numeric-owner', '-cf', '-', '-C', str(root), '.'],
                                stdout=output, stderr=subprocess.DEVNULL, timeout=30,
                                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        require(result.returncode == 0, 'legacy tree read failed')
        output.seek(0)
        require(hashlib.file_digest(output, 'sha256').hexdigest() == pin['treeSha256'],
                'legacy tree pin mismatch')


def runtime(pin, env, uid, gid):
    r = parse(pinned(pin, private=True))
    fields(r, 'version runsc legacyRootfs environment downloads')
    require(type(r['version']) is int and r['version'] == 1 and r['environment'] == env,
            'approved runtime environment mismatch')
    pinned(r['runsc'], executable=True)
    for path in (Path(r['runsc']['path']), *Path(r['runsc']['path']).parents):
        s = path.lstat()
        execute = 0o100 if s.st_uid == uid else (0o010 if s.st_gid == gid else 0o001)
        require(s.st_mode & execute, 'runsc is inaccessible to runtime identity')
    legacy(r['legacyRootfs'])
    require(env.get('PROVENANCE_RUNSC_PATH') == r['runsc']['path'] and
            env.get('PROVENANCE_ROOTFS') == r['legacyRootfs']['path'] and
            env.get('PROVENANCE_ROOTFS_IDENTITY') == 'sha256:' + r['legacyRootfs']['treeSha256'],
            'runtime environment binding')
    require(type(r['downloads']) is list and 2 <= len(r['downloads']) <= 16, 'download pin bound')
    prefixes = set()
    for item in r['downloads']:
        fields(item, 'prefix uri sha256 sizeBytes')
        prefix = item['prefix']
        require(prefix in ('PROVENANCE_PAPER_PROBE', 'PROVENANCE_PAPER_PREPARED_RUNTIME') and
                prefix not in prefixes, 'unsupported download pin')
        prefixes.add(prefix)
        uri = urlsplit(item['uri'])
        require(uri.scheme == 'https' and uri.hostname and not uri.username and not uri.password
                and not uri.fragment and not uri.query and type(item['sizeBytes']) is int and
                0 < item['sizeBytes'] <= 1 << 30 and re.fullmatch('[a-f0-9]{64}', item['sha256']),
                'unsafe download pin')
        require(all(env.get(prefix + '_' + key) == str(item[field]) for key, field in
                    [('URI', 'uri'), ('SHA256', 'sha256'), ('SIZE_BYTES', 'sizeBytes')]),
                'download environment binding')
    require('PROVENANCE_PAPER_PREPARED_RUNTIMES' not in env, 'multi-runtime composition not supported')
    writable = []
    for name in ('PROVENANCE_WORKSPACE_ROOT', 'PROVENANCE_CACHE_ROOT',
                 'PROVENANCE_GVISOR_STATE_ROOT', 'PROVENANCE_GVISOR_BUNDLE_ROOT'):
        path = canonical(env.get(name))
        ancestry(path)
        s = path.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == uid and s.st_gid == gid and
                stat.S_IMODE(s.st_mode) == 0o700, 'approved runtime directory identity')
        writable.append(path)
    require(len(set(writable)) == 4 and not any(a in c.parents for a in writable for c in writable),
            'overlapping runtime directories')
    require(re.fullmatch(r'[A-Za-z0-9.-]+(?:,[A-Za-z0-9.-]+)*', env.get('PROVENANCE_ARTIFACT_HOSTS', '')),
            'artifact host allowlist required')
    require(all(urlsplit(item['uri']).hostname in env['PROVENANCE_ARTIFACT_HOSTS'].split(',') and
                (urlsplit(item['uri']).port is None or 0 < urlsplit(item['uri']).port <= 65535)
                for item in r['downloads']), 'download host not approved')
    require(env.get('PROVENANCE_PAPER_PREPARED_RUNTIME_MAX_EXPANDED_BYTES', '').isdigit() and
            0 < int(env['PROVENANCE_PAPER_PREPARED_RUNTIME_MAX_EXPANDED_BYTES']) <= 1 << 30,
            'prepared runtime expansion bound required')
    return r


def load_plan(path, sha):
    p = parse(pinned({'path': path, 'sha256': sha}, private=True))
    fields(p, 'version uid gid destination stateDirectory unitDestination runner environment unit connect credential identity runtime')
    require(type(p['version']) is int and p['version'] == 1 and all(type(p[k]) is int and
            0 < p[k] < 4294967295 for k in ('uid', 'gid')), 'explicit nonroot identity required')
    require(pwd.getpwuid(p['uid']).pw_gid == p['gid'] and grp.getgrgid(p['gid']).gr_gid == p['gid'],
            'runtime identity mismatch')
    require(command('/usr/bin/pgrep', '-u', str(p['uid']), check=False).returncode == 1,
            'runtime identity has processes; no local stop is authorized')
    targets = [canonical(p[k]) for k in ('destination', 'stateDirectory', 'unitDestination')]
    for target in targets:
        ancestry(target)
    require(len(set(targets)) == 3 and not any(a in b.parents for a in targets for b in targets),
            'overlapping destinations')
    require(targets[2].parent == Path('/etc/systemd/system') and
            re.fullmatch(r'provenance-runner(?:-[a-z0-9-]{1,48})?\.service', targets[2].name),
            'unsupported system unit destination')
    inputs = {}
    for name in ('runner', 'environment', 'unit', 'connect', 'credential', 'identity'):
        inputs[name] = pinned(p[name], private=name != 'runner', executable=name == 'runner')
        source = Path(p[name]['path'])
        require(all(source != t and t not in source.parents for t in targets), 'input overlaps destination')
    require(inputs['unit'] == unit_bytes(p), 'unsupported unit composition')
    env = environment(inputs['environment'])
    runtime(p['runtime'], env, p['uid'], p['gid'])
    c = parse(inputs['connect'])
    fields(c, 'schemaVersion gatewayAddress runnerId instanceId credentialFile identityKeyFile expectedScope resources')
    require(c['schemaVersion'] == 'provenance.runner-connect/v1alpha1' and
            c['credentialFile'] in ('credential', p['stateDirectory'] + '/credential') and
            c['identityKeyFile'] in ('identity.json', p['stateDirectory'] + '/identity.json'),
            'connect credential reference mismatch')
    require(type(c['gatewayAddress']) is str and re.fullmatch(r'[a-zA-Z0-9.-]+:[0-9]{1,5}', c['gatewayAddress'])
            and 0 < int(c['gatewayAddress'].rsplit(':', 1)[1]) <= 65535, 'gateway authority required')
    require(re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', c['runnerId']), 'runner identity required')
    fields(c['expectedScope'], 'kind organizationId')
    require(c['expectedScope']['kind'] == 'organization' and
            re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', c['expectedScope']['organizationId']),
            'organization identity required')
    require(type(c['instanceId']) is str and 1 <= len(c['instanceId'].encode()) <= 128 and
            c['instanceId'] == c['instanceId'].strip(), 'instance identity bound')
    fields(c['resources'], 'cpuMillis memoryBytes diskBytes processCount')
    require(all(type(c['resources'][key]) is int and 0 < c['resources'][key] <= maximum for key, maximum in
                [('cpuMillis', 128000), ('memoryBytes', 1 << 40), ('diskBytes', 16 << 40), ('processCount', 1 << 20)]),
            'invalid resources')
    ident = parse(inputs['identity'])
    # Bind the reviewed references; cryptographic/expiry validation remains the
    # accepted runner loader's responsibility at separately authorized activation.
    require(ident.get('phase') == 'active' and ident.get('runnerId') == c['runnerId'] and
            ident.get('organizationId') == c['expectedScope']['organizationId'] and
            ident.get('response', {}).get('credentialSha256') == digest(inputs['credential']) and
            0 < len(inputs['credential']) <= 4096, 'credential identity binding')
    return p, inputs


def sync(p):
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def expected_objects(p, inputs):
    root, state = Path(p['destination']), Path(p['stateDirectory'])
    return [(root / 'runner', inputs['runner'], 0, 0, 0o555),
            (root / 'runner.env', inputs['environment'], 0, 0, 0o600),
            (state, None, p['uid'], p['gid'], 0o700),
            (state / 'connect.json', inputs['connect'], p['uid'], p['gid'], 0o600),
            (state / 'credential', inputs['credential'], p['uid'], p['gid'], 0o600),
            (state / 'identity.json', inputs['identity'], p['uid'], p['gid'], 0o600),
            (Path(p['unitDestination']), inputs['unit'], 0, 0, 0o600)]


def audit(p, sha, inputs, incomplete=False):
    root = Path(p['destination'])
    require(identity(root)['uid'] == 0 and identity(root)['mode'] == 0o755, 'baseline root drift')
    ledger = root / 'ownership.jsonl'
    rows = [parse(line) for line in read(ledger, private=True).splitlines()]
    require(rows and rows[0] == {'version': 1, 'planSha256': sha, 'root': identity(root),
                               'ledger': identity(ledger)},
            'ownership ledger mismatch')
    objects = expected_objects(p, inputs)
    complete = rows[-1] == {'complete': True}
    records = rows[1:-1] if complete else rows[1:]
    require(len(records) <= len(objects), 'unexpected ledger records')
    for row, (path, data, uid, gid, mode) in zip(records, objects):
        require(row == {'path': str(path), 'identity': identity(path),
                        'sha256': None if data is None else digest(data)} and
                identity(path)['uid'] == uid and identity(path)['gid'] == gid and
                identity(path)['mode'] == mode, 'owned object identity drift')
        if data is not None:
            require(read(path, owner=uid, maximum=512 << 20) == data, 'owned bytes drift')
    allowed_root = {'ownership.jsonl'} | {Path(r['path']).name for r in records if Path(r['path']).parent == root}
    require(set(x.name for x in root.iterdir()) == allowed_root, 'unrecorded retained root object')
    state = Path(p['stateDirectory'])
    if any(Path(r['path']) == state for r in records):
        require(set(x.name for x in state.iterdir()) ==
                {Path(r['path']).name for r in records if Path(r['path']).parent == state},
                'unrecorded runner state object')
    for path, *_ in objects[len(records):]:
        require(not os.path.lexists(path), 'unrecorded retained destination')
    require(incomplete or (complete and len(records) == len(objects)), 'incomplete baseline; owned state retained')
    return len(records), complete


def loaded(p):
    v = manager(Path(p['unitDestination']).name)
    require(v['LoadState'] == 'loaded' and v['UnitFileState'] == 'disabled' and
            v['FragmentPath'] == p['unitDestination'] and v['User'] == str(p['uid']) and
            v['Group'] == str(p['gid']) and v['NeedDaemonReload'] == 'no' and not v['Environment'] and
            v['EnvironmentFiles'] == p['destination'] + '/runner.env (ignore_errors=no)',
            'loaded unit identity mismatch')
    binary = p['destination'] + '/runner'
    argv = binary + ' connect ' + p['stateDirectory'] + '/connect.json'
    require(re.fullmatch(r'\{ path=' + re.escape(binary) + r' ; argv\[\]=' + re.escape(argv) +
                        r' ; ignore_errors=no ; start_time=\[n/a\] ; stop_time=\[n/a\] ; pid=0 ; code=\(null\) ; status=0/0 \}',
                        v['ExecStart']), 'loaded command mismatch')


def install(p, sha, inputs):
    root = Path(p['destination'])
    if os.path.lexists(root):
        audit(p, sha, inputs)
        loaded(p)
        return {'status': 'exact-repeat', 'started': False}
    before = manager(Path(p['unitDestination']).name)
    require(before['LoadState'] == 'not-found' and not before['FragmentPath'], 'existing loaded unit')
    for path in (Path(p['stateDirectory']), Path(p['unitDestination'])):
        require(not os.path.lexists(path), 'existing destination')
    # Also detect fragments not yet reloaded, including vendor units and generic
    # service drop-ins. Manager introspection alone misses pending filesystem work.
    name = Path(p['unitDestination']).name
    parts = name.removesuffix('.service').split('-')
    dropins = ['service.d', name + '.d'] + [
        '-'.join(parts[:i]) + '-.service.d' for i in range(1, len(parts))]
    for directory in command('/usr/bin/systemd-analyze', 'unit-paths').stdout.splitlines():
        base = Path(directory)
        require(not os.path.lexists(base / name), 'conflicting unit fragment')
        for dropin in dropins:
            require(not os.path.lexists(base / dropin), 'conflicting unit drop-in')
        if base.exists():
            for entry in base.iterdir():
                if entry.name.endswith(('.wants', '.requires', '.upholds')):
                    require(not os.path.lexists(entry / name), 'pending service enablement')
                if entry.is_symlink():
                    require(entry.resolve() != Path(p['unitDestination']), 'conflicting service alias')
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    sync(root.parent)
    ledger = root / 'ownership.jsonl'
    fd = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        def record(value):
            data = encoded(value)
            require(os.write(fd, data) == len(data), 'ledger short write; state retained')
            os.fsync(fd)
            sync(root)
        record({'version': 1, 'planSha256': sha, 'root': identity(root), 'ledger': identity(ledger)})
        for path, data, uid, gid, mode in expected_objects(p, inputs):
            if data is None:
                path.mkdir(mode=0o700)
                os.chown(path, uid, gid, follow_symlinks=False)
            else:
                newfd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
                try:
                    os.fchown(newfd, uid, gid)
                    os.fchmod(newfd, mode)
                    with os.fdopen(os.dup(newfd), 'wb') as stream:
                        stream.write(data)
                        stream.flush()
                    os.fsync(newfd)
                finally:
                    os.close(newfd)
            sync(path.parent)
            record({'path': str(path), 'identity': identity(path),
                    'sha256': None if data is None else digest(data)})
        command('/usr/bin/systemctl', '--system', 'daemon-reload')
        loaded(p)
        record({'complete': True})
    finally:
        os.close(fd)
    audit(p, sha, inputs)
    return {'status': 'installed-disabled-stopped', 'started': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'verify', 'recover'))
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'root operator required')
        os.umask(0o077)
        p, inputs = load_plan(args.plan, args.plan_sha256)
        # Lock an existing protected parent; no unowned lockfile is created or
        # adopted and concurrent baselines in that parent serialize harmlessly.
        lock = os.open(Path(p['destination']).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.action == 'install':
                result = install(p, args.plan_sha256, inputs)
            elif args.action == 'verify':
                audit(p, args.plan_sha256, inputs)
                loaded(p)
                result = {'status': 'verified-disabled-stopped', 'started': False}
            else:
                manager(Path(p['unitDestination']).name)
                count, complete = audit(p, args.plan_sha256, inputs, incomplete=True)
                result = {'status': 'retained-owned-state', 'objects': count, 'complete': complete,
                          'removed': 0, 'resumed': False}
        finally:
            os.close(lock)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Refusal as error:
        print('baseline refused: ' + str(error) + '; created state retained', file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        # Never include parser/OS/manager errors: they may embed protected data.
        print('baseline refused; any created state is retained for exact ownership inspection', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
