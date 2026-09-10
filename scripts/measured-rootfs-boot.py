#!/usr/bin/env python3
"""Restore a pinned, already-selected rootfs before the user runner starts.

No installer, selector, unmount, loop detach, runner restart, or remote drain.
Root/systemd are trusted. Installation/selection requires a separate drained
operation; this helper only reestablishes that selection after a reboot.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import struct
import subprocess
import sys

spec = importlib.util.spec_from_file_location(
    'generation', Path(__file__).with_name('runtime-generation.py'))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
require = g.require


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=90, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                           'LC_ALL': 'C'}).stdout.strip()


def safe_path(value, mount_unit=False):
    pattern = (r'/etc/systemd/system/(?:[A-Za-z0-9_.-]|\\x[0-9a-f]{2})+\.mount'
               if mount_unit else r'/[A-Za-z0-9_./-]+')
    require(isinstance(value, str) and re.fullmatch(pattern, value)
            and str(Path(value)) == value and Path(value).resolve() == Path(value)
            and value != '/', 'unsafe path')
    return Path(value)


def unit_bytes(p):
    # Explicit loop mounting lets systemd recreate an autoclear mapping at boot.
    # No Before=runner dependency: the wrapper synchronously starts this mount
    # from ExecStartPre, before starting the otherwise disabled user unit.
    return ('[Unit]\nDescription=Provenance measured root filesystem\n\n'
            '[Mount]\nWhat=' + p['image']['path'] + '\nWhere=' + p['rootfs'] +
            '\nType=squashfs\nOptions=loop,ro,nosuid,nodev\nTimeoutSec=60\n').encode()


def runtime_values(p):
    return {'PROVENANCE_RUNSC_PATH': p['runsc']['path'],
            'PROVENANCE_ROOTFS': p['rootfs'],
            'PROVENANCE_ROOTFS_IDENTITY': 'sha256:' + p['image']['sha256'],
            'PROVENANCE_MEASURED_RUNTIME_MODE': 'embedded-executable',
            'PROVENANCE_GVISOR_CGROUP_DRIVER': 'systemd-user',
            'PROVENANCE_MEASURED_ROOTFS_IMAGE': p['image']['path'],
            'PROVENANCE_MEASURED_LOOP_DEVICE': p['loop']}


def environment(data, owned):
    # Narrow installed-file grammar, not a shell or general systemd parser.
    # Each assignment is one complete line. This prevents continuation/quoted
    # multiline syntax from hiding or swallowing an apparently pinned setting.
    require(len(data) <= 512 * 1024 and b'\0' not in data and b'\r' not in data and
            (not data or data.endswith(b'\n')), 'environment encoding/bound')
    values, other = {}, []
    for line in data.splitlines(keepends=True):
        if line.strip() == b'' or line.startswith((b'#', b';')):
            other.append(line)
            continue
        match = re.fullmatch(rb'([A-Z][A-Z0-9_]*)=([^\n]*)\n', line)
        require(match is not None, 'environment assignment')
        key, raw = match[1].decode('ascii'), match[2].decode('utf-8')
        require(key not in values, 'duplicate environment assignment')
        if raw.startswith('"'):
            value = json.loads(raw)
            require(isinstance(value, str), 'environment string')
        else:
            require(re.fullmatch(r'[A-Za-z0-9_:/.,@+=%-]*', raw), 'environment value syntax')
            value = raw
        values[key] = value
        if key not in owned:
            other.append(line)
    return values, other


def render_environment(p, before):
    expected = runtime_values(p)
    _, other = environment(before, expected)
    return b''.join(other) + ''.join(k + '=' + v + '\n' for k, v in sorted(expected.items())).encode()


def selected_environment(p):
    path = g.protected(p['runtimeEnvironment'])
    s = path.stat()
    require(s.st_gid == p['gid'] and stat.S_IMODE(s.st_mode) == 0o640 and
            s.st_nlink == 1 and s.st_size <= 512 * 1024, 'environment custody/bound')
    expected = runtime_values(p)
    actual, _ = environment(path.read_bytes(), expected)
    require(all(actual.get(k) == v for k, v in expected.items()), 'runtime selection mismatch')


def load_plan(path, digest, require_selection=True):
    p = g.read_json(path, digest)
    require(isinstance(p, dict), 'plan object required')
    fields = {'version', 'generation', 'uid', 'gid', 'image',
              'imageManifest', 'rootfs', 'loop', 'mountUnit', 'userUnit'}
    if p.get('version') == 2:
        fields |= {'runtimeEnvironment', 'runsc'}
    require(set(p) == fields,
            'plan fields')
    require(type(p['version']) is int and p['version'] in (1, 2) and
            all(type(p[k]) is int and 0 < p[k] < 4294967295 for k in ('uid', 'gid')),
            'runtime identity')
    account = pwd.getpwuid(p['uid'])
    require(account.pw_gid == p['gid'], 'runtime primary group drift')
    for key in ('image', 'imageManifest', 'mountUnit', 'userUnit'):
        item = p[key]
        require(isinstance(item, dict) and set(item) == {'path', 'sha256'} and
                isinstance(item['sha256'], str) and
                re.fullmatch('[a-f0-9]{64}', item['sha256']), 'pin fields')
        safe_path(item['path'], mount_unit=key == 'mountUnit')
        g.fingerprint(item['path'], item['sha256'])
    generation = g.protected(safe_path(p['generation']), True)
    s = generation.stat()
    require(s.st_gid == p['gid'] and stat.S_IMODE(s.st_mode) == 0o710 and
            generation.name == 'sha256-' + p['image']['sha256'], 'generation identity')
    require(p['image']['path'] == str(generation / 'image.squashfs') and
            p['imageManifest']['path'] == str(generation / 'image-manifest.json') and
            p['rootfs'] == str(generation / 'rootfs') and
            p['loop'] == str(generation / 'loop'), 'generation layout')
    safe_path(p['rootfs'])
    safe_path(p['loop'])
    image = Path(p['image']['path']).stat()
    require(image.st_gid == p['gid'] and stat.S_IMODE(image.st_mode) == 0o440
            and image.st_nlink == 1, 'image custody')
    manifest = g.read_json(p['imageManifest']['path'], p['imageManifest']['sha256'])
    require(manifest.get('format') == 'squashfs-image-sha256/v1' and
            manifest.get('sha256') == p['image']['sha256'] and
            manifest.get('sizeBytes') == image.st_size and
            manifest.get('runnerUid') == p['uid'] and manifest.get('runnerGid') == p['gid']
            and manifest.get('reproducibleBuilds') == 2, 'image build identity')
    name = run('systemd-escape', '--path', '--suffix=mount', p['rootfs'])
    require(p['mountUnit']['path'] == '/etc/systemd/system/' + name and
            Path(p['mountUnit']['path']).read_bytes() == unit_bytes(p), 'mount unit binding')
    require(p['userUnit']['path'] == '/etc/systemd/user/provenance-runner.service',
            'runner user unit binding')
    if p['version'] == 2:
        require(p['runtimeEnvironment'] == '/opt/provenance-runner/runner.env' and
                set(p['runsc']) == {'path', 'sha256'} and
                p['runsc']['path'] == '/opt/provenance-runner/runsc' and
                re.fullmatch('[a-f0-9]{64}', p['runsc']['sha256']), 'hosted runtime binding')
        g.fingerprint(p['runsc']['path'], p['runsc']['sha256'], executable=True)
        if require_selection:
            selected_environment(p)
    return p


def userctl(p, *args):
    account = pwd.getpwuid(p['uid'])
    return run('runuser', '-u', account.pw_name, '--', 'env',
               'XDG_RUNTIME_DIR=/run/user/' + str(p['uid']),
               'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(p['uid']) + '/bus',
               'systemctl', '--user', *args)


def loaded_unit(p, key, ctl):
    item = p[key]
    g.fingerprint(item['path'], item['sha256'])
    name = Path(item['path']).name
    for prop, expected in (('FragmentPath', item['path']), ('DropInPaths', ''),
                           ('NeedDaemonReload', 'no')):
        require(ctl('show', name, '--property=' + prop, '--value') == expected,
                'loaded unit drift')


def quiet(p):
    loaded_unit(p, 'userUnit', lambda *args: userctl(p, *args))
    require(userctl(p, 'show', 'provenance-runner.service', '--property=ActiveState',
                    '--value') in ('inactive', 'failed'), 'runner must be stopped')
    rows = userctl(p, 'list-units', '--type=scope', '--state=active,activating,deactivating',
                   '--no-legend', '--plain').splitlines()
    require(not rows or (len(rows) == 1 and
                        rows[0].split()[:4] == ['init.scope', 'loaded', 'active', 'running']),
            'runtime scopes remain')


def loop_identity(loop, image):
    require(re.fullmatch('/dev/loop[0-9]+', loop), 'unexpected mount source')
    source = Path(image).stat()
    fd = os.open(loop, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        node = os.fstat(fd)
        buf = bytearray(232)
        fcntl.ioctl(fd, 0x4C05, buf, True)  # LOOP_GET_STATUS64
        info = struct.unpack('=QQQQQIIII64s64s32sQQ', buf)
        require(stat.S_ISBLK(node.st_mode) and os.major(node.st_rdev) == 7 and
                os.minor(node.st_rdev) == info[5] and info[0] == source.st_dev and
                info[1] == source.st_ino and info[3:5] == (0, 0) and
                info[6:8] == (0, 0) and info[8] in (1, 5),
                'loop backing/flags drift')  # READ_ONLY, optionally AUTOCLEAR
        return node.st_rdev
    finally:
        os.close(fd)


def mounted(p):
    m = g.mount_info(p['rootfs'])
    require(m['fstype'] == 'squashfs' and
            {'ro', 'nosuid', 'nodev'} <= set(m['options'].split(',')), 'mount flags drift')
    device = loop_identity(m['source'], p['image']['path'])
    require(m['maj:min'] == f'{os.major(device)}:{os.minor(device)}', 'mount device drift')
    descendants = run('findmnt', '--submounts', '--raw', '--noheadings', '--output',
                      'TARGET', '--mountpoint', p['rootfs']).splitlines()
    require(descendants == [p['rootfs']], 'nested mount')
    return device


def private_node(p, device, repair):
    node = Path(p['loop'])
    try:
        s = node.lstat()
    except FileNotFoundError:
        s = None
    if s is not None:
        require(stat.S_ISBLK(s.st_mode) and s.st_uid == 0 and s.st_gid == p['gid'] and
                stat.S_IMODE(s.st_mode) == 0o440 and s.st_nlink == 1 and
                os.major(s.st_rdev) == 7, 'private node custody drift')
        if s.st_rdev == device:
            return
    require(repair, 'private node mapping drift')
    # Reboot may reuse the old global loop number. Replace only our private alias;
    # never detach, chmod or otherwise modify that global device or its mapping.
    temporary = node.with_name('.loop.pending')
    os.mknod(temporary, stat.S_IFBLK | 0o400, device)  # exclusive: EEXIST refuses
    created = temporary.lstat()
    try:
        os.chown(temporary, 0, p['gid'], follow_symlinks=False)
        os.chmod(temporary, 0o440)
        os.replace(temporary, node)
        g.sync_directory(node.parent)
    except Exception:
        try:
            current = temporary.lstat()
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def execute(p, action):
    loaded_unit(p, 'mountUnit', lambda *args: run('systemctl', *args))
    if action == 'ensure':
        quiet(p)
        name = Path(p['mountUnit']['path']).name
        state = run('systemctl', 'show', name, '--property=ActiveState', '--value')
        require(state in ('active', 'inactive', 'failed'), 'mount transition in progress')
        if state != 'active':
            # Refuse a foreign mount or hidden data before starting our exact unit.
            require(not os.path.ismount(p['rootfs']), 'unmanaged existing mount')
            root = g.protected(p['rootfs'], True)
            require(not any(root.iterdir()), 'nonempty mountpoint')
            run('systemctl', 'start', name)
        device = mounted(p)
        quiet(p)
        private_node(p, device, True)
    device = mounted(p)
    private_node(p, device, False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('ensure', 'verify'))
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'root required')
    require(re.fullmatch('[a-f0-9]{64}', args.plan_sha256), 'plan digest')
    p = load_plan(args.plan, args.plan_sha256)
    fd = os.open(p['generation'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        p = load_plan(args.plan, args.plan_sha256)
        execute(p, args.action)
    finally:
        os.close(fd)
    print(json.dumps({'action': args.action, 'imageSha256': p['image']['sha256'],
                      'verified': True}))


if __name__ == '__main__':
    try:
        main()
    except (g.Refusal, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError):
        # In particular never forward subprocess stderr or environment content.
        print('measured rootfs boot refused; inspect protected inputs and unit state', file=sys.stderr)
        sys.exit(1)
