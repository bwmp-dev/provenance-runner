#!/usr/bin/env python3
"""Offline, opt-in runtime generation management. Never starts a service.

Privileged callers supply a reviewed plan and a separately hash-pinned fresh
control-plane drain record. Root and the kernel are trusted, not adversarial.
An install creates a new generation; select/rollback only replace the explicitly
pinned environment file. No credentials, remote queries or policy changes occur.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import pwd
import grp
import struct


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},
                          timeout=30).stdout.strip()


def protected(value, directory=False):
    p = Path(value)
    require(p.is_absolute() and p != Path('/') and p.resolve() == p,
            'noncanonical path')
    for ancestor in p.parents:
        s = ancestor.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'unprotected ancestry')
    s = p.lstat()
    require((stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
            and s.st_uid == 0 and not s.st_mode & 0o6022, 'unprotected object')
    return p


def fingerprint(path, expected=None, executable=False):
    p = protected(path)
    with p.open('rb') as f:
        before = os.fstat(f.fileno())
        require(before.st_size <= 4 << 30, 'object size limit')
        if executable:
            require(before.st_size <= 512 << 20 and f.read(4) == b'\x7fELF' and before.st_mode & 0o111,
                    'direct executable ELF required')
            f.seek(0)
        digest = hashlib.file_digest(f, 'sha256').hexdigest()
        after = os.fstat(f.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                         after.st_mtime_ns, after.st_ctime_ns), 'object changed')
    require(expected is None or digest == expected, 'object digest mismatch')
    return {'sha256': digest, 'device': before.st_dev, 'inode': before.st_ino,
            'size': before.st_size}


def read_json(path, expected=None):
    fingerprint(path, expected)
    require(Path(path).stat().st_size <= 65536, 'JSON bound')
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, 'duplicate JSON member')
            result[k] = v
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=pairs)


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    sync_directory(Path(path).parent)


def sync_directory(path):
    fd=os.open(path,os.O_RDONLY | os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def load_plan(path, digest):
    p = read_json(path, digest)
    require(set(p) == {'version', 'generation', 'uid', 'gid', 'runner', 'currentRunner', 'runsc',
                       'image', 'currentConfig', 'newConfig', 'unit', 'newUnit', 'legacyRootfs', 'imageManifest'},
            'plan fields')
    require(p['version'] == 1 and type(p['uid']) is int and type(p['gid']) is int
            and 1 <= p['uid'] < 4294967295 and 1 <= p['gid'] < 4294967295,
            'plan identity')
    for name in ('runner', 'currentRunner', 'runsc', 'image', 'currentConfig', 'newConfig', 'unit', 'newUnit', 'imageManifest'):
        item = p[name]
        require(set(item) == {'path', 'sha256'} and
                re.fullmatch('[a-f0-9]{64}', item['sha256']), 'pin fields')
        if name not in ('currentConfig','unit'):
            fingerprint(item['path'], item['sha256'], name in ('runner', 'currentRunner', 'runsc'))
    require(set(p['legacyRootfs']) == {'path', 'treeSha256'} and
            re.fullmatch('[a-f0-9]{64}', p['legacyRootfs']['treeSha256']), 'legacy pin')
    root=Path(p['legacyRootfs']['path'])
    require(root.is_absolute() and root.resolve()==root and root != Path('/'), 'legacy path')
    protected(root.parent,True)
    require(root.lstat().st_uid in (0,p['uid']) and root.is_dir() and
            not root.lstat().st_mode & 0o022, 'legacy owner/mode')
    dest = Path(p['generation'])
    require(dest.is_absolute() and dest.resolve() == dest and
            re.fullmatch('sha256-[a-f0-9]{64}', dest.name), 'generation destination')
    protected(dest.parent, True)
    require(dest.name == 'sha256-' + p['image']['sha256'], 'generation image binding')
    require(len({str(dest), *(str(Path(p[n]['path'])) for n in
                            ('runner','runsc','image','currentConfig','newConfig','unit','newUnit','imageManifest'))}) == 9,
            'overlapping input paths')
    for name in ('runner','currentRunner','runsc','image','currentConfig','newConfig','unit','newUnit','imageManifest'):
        require(dest not in Path(p[name]['path']).parents, 'input inside managed generation')
    require(fingerprint(p['currentConfig']['path'])['sha256'] in
            (p['currentConfig']['sha256'],p['newConfig']['sha256']), 'current config drift')
    require(fingerprint(p['unit']['path'])['sha256'] in
            (p['unit']['sha256'],p['newUnit']['sha256']), 'current unit drift')
    manifest = read_json(p['imageManifest']['path'], p['imageManifest']['sha256'])
    require(manifest.get('sha256') == p['image']['sha256'] and
            manifest.get('sizeBytes') == fingerprint(p['image']['path'])['size'] and
            manifest.get('runnerUid') == p['uid'] and manifest.get('runnerGid') == p['gid']
            and manifest.get('reproducibleBuilds') == 2 and
            manifest.get('format') == 'squashfs-image-sha256/v1', 'image build identity')
    return p


def drained(p, plan_sha, evidence_path, evidence_sha):
    d = read_json(evidence_path, evidence_sha)
    require(set(d) == {'version', 'planSha256', 'issuedAt', 'expiresAt',
                       'platformDrainEvidenceSha256', 'activeLeases', 'pendingTerminalReplay'},
            'drain fields')
    require(d['version'] == 1 and d['planSha256'] == plan_sha and
            type(d['issuedAt']) is int and type(d['expiresAt']) is int and
            d['issuedAt'] <= time.time() < d['expiresAt'] <= d['issuedAt'] + 300 and
            re.fullmatch('[a-f0-9]{64}', d['platformDrainEvidenceSha256']) and
            type(d['activeLeases']) is int and d['activeLeases'] == 0 and
            type(d['pendingTerminalReplay']) is int and d['pendingTerminalReplay'] == 0,
            'fresh complete coordinator drain required')
    unit = Path(p['unit']['path'])
    require(unit.suffix == '.service', 'explicit service unit required')
    fragment = run('systemctl', 'show', unit.name, '--property=FragmentPath', '--value')
    require(fragment == str(unit), 'unit identity drift')
    require(run('systemctl','show',unit.name,'--property=DropInPaths','--value') == '',
            'unreviewed unit drop-ins')
    user=run('systemctl','show',unit.name,'--property=User','--value')
    group=run('systemctl','show',unit.name,'--property=Group','--value')
    require(user != '' and group != '', 'explicit service user and group required')
    require((int(user) if user.isdecimal() else pwd.getpwnam(user).pw_uid)==p['uid'] and
            (int(group) if group.isdecimal() else grp.getgrnam(group).gr_gid)==p['gid'],
            'service runtime identity mismatch')
    require(run('systemctl', 'show', unit.name, '--property=ActiveState', '--value')
            in ('inactive', 'failed'), 'service must be stopped')
    require(run('systemctl','show',f"user@{p['uid']}.service",'--property=ActiveState','--value')
            in ('inactive','failed'), 'runtime user manager must be stopped')
    # Fail closed even on user-manager/helper processes. Operator stops the
    # drained runtime user manager separately; this tool never kills anything.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            require(entry.stat().st_uid != p['uid'], 'runtime UID still has processes')
        except FileNotFoundError:
            pass


def mount_info(root):
    values = json.loads(run('findmnt', '--json', '--mountpoint', str(root),
                            '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN'))
    rows = values.get('filesystems', [])
    require(len(rows) == 1 and rows[0]['target'] == str(root), 'exact mount required')
    return rows[0]


def mapping(loop):
    rows = json.loads(run('losetup', '--json', '--list', '--output',
                         'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT,RO', loop))['loopdevices']
    require(len(rows) == 1 and rows[0]['name'] == loop, 'exact loop required')
    return rows[0]


def verify_mapping(loop, image):
    m = mapping(loop)
    s = Path(image).stat()
    require(m['back-file'] == str(image) and int(m['back-ino']) == s.st_ino
            and m['back-maj:min'] == f'{os.major(s.st_dev)}:{os.minor(s.st_dev)}'
            and int(m['offset']) == 0 and int(m['sizelimit']) == 0 and
            m['ro'] in (True, 1, '1'), 'loop backing drift')
    # Linux loop_info64, independent of losetup's display fields. In particular
    # do not infer "unencrypted whole image" from a matching displayed path.
    fd=os.open(loop,os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        buf=bytearray(232)
        fcntl.ioctl(fd,0x4C05,buf,True)  # LOOP_GET_STATUS64
        info=struct.unpack('=QQQQQIIII64s64s32sQQ',buf)
        node=os.fstat(fd)
        require(stat.S_ISBLK(node.st_mode) and os.major(node.st_rdev)==7 and
                os.minor(node.st_rdev)==info[5] and info[0]==s.st_dev and info[1]==s.st_ino
                and info[3]==0 and info[4]==0 and info[6]==0 and info[7]==0 and info[8]==1,
                'loop ioctl identity/flags drift')
    finally:os.close(fd)
    return m


def legacy(p):
    root = p['legacyRootfs']['path']
    m = mount_info(root)
    require('ro' in m['options'].split(','), 'legacy mount is not read-only')
    # Reuse the accepted normalized-tree definition, not image-hash identity.
    process = subprocess.Popen(['tar', '--sort=name', '--format=gnu', '--mtime=@0',
                                '--owner=0', '--group=0', '--numeric-owner', '-cf', '-',
                                '-C', root, '.'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    h = hashlib.file_digest(process.stdout, 'sha256').hexdigest()
    require(process.wait(timeout=30) == 0 and h == p['legacyRootfs']['treeSha256'],
            'legacy tree identity drift')


def verify(p, plan_sha, allow_pending=False):
    dest = protected(p['generation'], True)
    state = read_json(dest / 'state.json')
    require(allow_pending or not (dest/'pending.json').exists(), 'incomplete generation')
    require(not (dest/'detached.json').exists(), 'generation was detached')
    require(set(state) == {'version', 'planSha256', 'loop', 'objects'} and
            state['version'] == 1 and state['planSha256'] == plan_sha, 'generation state mismatch')
    for name in ('runner', 'runsc', 'image'):
        require(fingerprint(dest / name, p[name]['sha256'], name != 'image') ==
                state['objects'][name], 'generation object drift')
    loop = state['loop']
    require(re.fullmatch('/dev/loop[0-9]+', loop), 'loop name')
    verify_mapping(loop, dest / 'image')
    node = dest / 'loop'
    ns = node.lstat()
    require(stat.S_ISBLK(ns.st_mode) and ns.st_rdev == Path(loop).stat().st_rdev and
            ns.st_uid == 0 and ns.st_gid == p['gid'] and stat.S_IMODE(ns.st_mode) == 0o440,
            'private loop node drift')
    m = mount_info(dest / 'rootfs')
    require(m['fstype'] == 'squashfs' and {'ro','nosuid','nodev'} <= set(m['options'].split(','))
            and m['maj:min'] == f'{os.major(ns.st_rdev)}:{os.minor(ns.st_rdev)}', 'mount identity drift')
    descendants = run('findmnt', '--submounts', '--raw', '--noheadings', '--output',
                      'TARGET', '--mountpoint', str(dest / 'rootfs')).splitlines()
    require(descendants == [str(dest / 'rootfs')], 'nested mounts')
    return state


def config_delta(p, old, new):
    # Preserve every unrelated byte, including comments and line endings. Only
    # these established runner environment assignments may change. No shell is
    # ever invoked to parse either document.
    dest = p['generation']
    values = {'PROVENANCE_RUNSC_PATH': dest+'/runsc',
              'PROVENANCE_ROOTFS': dest+'/rootfs',
              'PROVENANCE_ROOTFS_IDENTITY': 'sha256:'+p['image']['sha256'],
              'PROVENANCE_MEASURED_RUNTIME_MODE': 'embedded-executable',
              'PROVENANCE_GVISOR_CGROUP_DRIVER': 'systemd-user',
              'PROVENANCE_MEASURED_ROOTFS_IMAGE': dest+'/image',
              'PROVENANCE_MEASURED_LOOP_DEVICE': dest+'/loop'}
    def split(data):
        require(len(data) <= 65536 and b'\x00' not in data, 'config bound')
        other, selected = [], {}
        for line in data.splitlines(keepends=True):
            key = line.split(b'=',1)[0].decode('ascii', errors='replace')
            for owned in values:
                if re.match(rb'^\s*(?:export\s+)?[\"\x27]?'+owned.encode()+rb'[\"\x27]?\s*=',line):
                    require(line.startswith(owned.encode()+b'='),'ambiguous runtime assignment')
            if key in values:
                require(key not in selected, 'duplicate runtime setting')
                selected[key] = line
            else:
                other.append(line)
        return other, selected
    a, _ = split(old)
    b, actual = split(new)
    require(a == b and set(actual) == set(values), 'unrelated configuration delta')
    for key, value in values.items():
        require(re.fullmatch(r'[A-Za-z0-9_:./-]+', value) and
                actual[key] == (key+'='+value+'\n').encode(), 'runtime setting identity')


def unit_delta(p,old,new):
    require(len(old)<=65536 and len(new)<=65536 and b'\x00' not in old+new,'unit bound')
    def split(data):
        found=[]
        for line in data.splitlines(keepends=True):
            if line.lstrip().startswith(b'ExecStart'):
                require(line.startswith(b'ExecStart=') and not any(c in line for c in (b'\\',b'%',b'\r')),
                        'ambiguous ExecStart')
                found.append(line)
        require(len(found)==1,'single ExecStart required')
        return found[0]
    a,b=split(old),split(new)
    oldpath=p['currentRunner']['path']
    newpath=p['generation']+'/runner'
    for path in (oldpath,newpath):require(re.fullmatch(r'/[A-Za-z0-9_./-]+',path),'unit binary path')
    prefix=b'ExecStart='+oldpath.encode()
    require(a.startswith(prefix) and a[len(prefix):len(prefix)+1] in (b' ',b'\n'), 'old executable identity')
    expected=b'ExecStart='+newpath.encode()+a[len(prefix):]
    require(b==expected and old.replace(a,expected,1)==new,'unrelated unit delta')
    setting=('EnvironmentFile='+p['currentConfig']['path']+'\n').encode()
    matches=[line for line in old.splitlines(keepends=True) if line.lstrip().startswith(b'EnvironmentFile')]
    require(matches==[setting],'unit must select exact configuration file')


def replace_file(path, expected, data):
    path = protected(path)
    fingerprint(path, expected)
    st = path.stat()
    temp = path.parent / ('.'+path.name+'.runtime-generation')
    # Own the exclusive descriptor before any operation that can fail. General
    # write_new journals intentionally retain partial state; replacement temps
    # have a different lifecycle and must not poison an exact retry.
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, stat.S_IMODE(st.st_mode))
    created = None
    installed = False
    try:
        created = os.fstat(fd)
        output = os.fdopen(fd, 'wb')
        fd = -1  # output now owns the descriptor, including exceptional close.
        with output:
            output.write(data)
            output.flush()
            os.fchown(output.fileno(), st.st_uid, st.st_gid)
            os.fsync(output.fileno())
        sync_directory(path.parent)
        current = temp.lstat()
        require((current.st_dev, current.st_ino) == (created.st_dev, created.st_ino),
                'replacement temp identity drift')
        fingerprint(path, expected)
        os.replace(temp, path)
        installed = True
        sync_directory(path.parent)
    finally:
        if fd != -1:
            os.close(fd)
        if not installed:
            # Never erase a substituted, foreign or unidentifiable object.
            # After successful replace, a failed directory sync is reported,
            # but the selected bytes are not blindly rolled back.
            protected(path.parent, True)
            current = temp.lstat()
            require(created is not None and (current.st_dev, current.st_ino) ==
                    (created.st_dev, created.st_ino), 'replacement cleanup identity drift')
            temp.unlink()
            sync_directory(path.parent)


def select(p, plan_sha):
    verify(p, plan_sha)
    dest = Path(p['generation'])
    old = (dest / 'previous.env').read_bytes()
    new = protected(p['newConfig']['path']).read_bytes()
    require(hashlib.sha256(old).hexdigest() == p['currentConfig']['sha256'], 'backup drift')
    config_delta(p, old, new)
    oldunit=protected(dest/'previous.service').read_bytes()
    newunit=protected(p['newUnit']['path']).read_bytes()
    require(hashlib.sha256(oldunit).hexdigest()==p['unit']['sha256'],'unit backup drift')
    unit_delta(p,oldunit,newunit)
    current = fingerprint(p['currentConfig']['path'])['sha256']
    require(current in (p['currentConfig']['sha256'], p['newConfig']['sha256']), 'current config drift')
    if current != p['newConfig']['sha256']:
        replace_file(p['currentConfig']['path'], current, new)
    currentunit=fingerprint(p['unit']['path'])['sha256']
    require(currentunit in (p['unit']['sha256'],p['newUnit']['sha256']),'unit drift')
    if currentunit!=p['newUnit']['sha256']:
        replace_file(p['unit']['path'],currentunit,newunit)
    if currentunit!=p['newUnit']['sha256'] or run('systemctl','show',Path(p['unit']['path']).name,
                                                '--property=NeedDaemonReload','--value')=='yes':
        run('systemctl','daemon-reload')


def detach(p, plan_sha, incomplete=False):
    dest = protected(p['generation'], True)
    expected = {'pending.json','allocated.json','state.json','runner','runsc','image',
                'rootfs','loop','previous.env','previous.service','detached.json'}
    require({x.name for x in dest.iterdir()} <= expected, 'foreign generation entries')
    pinfile = dest / ('pending.json' if incomplete else 'state.json')
    journal = read_json(pinfile)
    require(journal.get('planSha256') == plan_sha, 'generation journal drift')
    for name in ('runner','runsc','image'):
        if (dest/name).exists():
            fingerprint(dest/name, p[name]['sha256'], name != 'image')
    root = dest/'rootfs'
    # Already detached rollback is idempotent, but still checks every retained
    # source object and current configuration. No resources are deleted here.
    associated = []
    if (dest/'image').exists():
        associated = run('losetup','--noheadings','--output','NAME','--associated',str(dest/'image')).splitlines()
    require(len(associated) <= 1, 'ambiguous loop mappings')
    ismount = subprocess.run(['mountpoint','--quiet',str(root)], check=False).returncode == 0
    if ismount:
        require(len(associated) == 1, 'foreign mount')
        loop = associated[0]
        verify_mapping(loop, dest/'image')
        m = mount_info(root)
        s = Path(loop).stat()
        require(m['fstype'] == 'squashfs' and m['maj:min'] ==
                f'{os.major(s.st_rdev)}:{os.minor(s.st_rdev)}', 'foreign mount device')
        require(run('findmnt','--submounts','--raw','--noheadings','--output','TARGET',
                    '--mountpoint',str(root)).splitlines() == [str(root)], 'nested mount')
        run('umount', str(root))  # no lazy/force unmount; busy is a refusal
    for loop in associated:
        verify_mapping(loop, dest/'image')
        # Refuse any remaining alias mount, including an outside bind mount.
        dev = Path(loop).stat().st_rdev
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            require(line.split()[2] != f'{os.major(dev)}:{os.minor(dev)}', 'loop still mounted')
        run('losetup','--detach',loop)
        require(not run('losetup','--noheadings','--output','NAME','--associated',str(dest/'image')),
                'loop remains associated')
    if not (dest/'detached.json').exists():
        write_new(dest/'detached.json', encoded({'version':1,'planSha256':plan_sha}))


def rollback(p, plan_sha):
    dest = protected(p['generation'], True)
    old = protected(dest/'previous.env').read_bytes()
    require(hashlib.sha256(old).hexdigest() == p['currentConfig']['sha256'], 'backup drift')
    current = fingerprint(p['currentConfig']['path'])['sha256']
    require(current in (p['currentConfig']['sha256'],p['newConfig']['sha256']), 'current config drift')
    if current != p['currentConfig']['sha256']:
        replace_file(p['currentConfig']['path'],current,old)
    oldunit=protected(dest/'previous.service').read_bytes()
    require(hashlib.sha256(oldunit).hexdigest()==p['unit']['sha256'],'unit backup drift')
    currentunit=fingerprint(p['unit']['path'])['sha256']
    require(currentunit in (p['unit']['sha256'],p['newUnit']['sha256']),'unit drift')
    if currentunit!=p['unit']['sha256']:
        replace_file(p['unit']['path'],currentunit,oldunit)
    if currentunit!=p['unit']['sha256'] or run('systemctl','show',Path(p['unit']['path']).name,
                                            '--property=NeedDaemonReload','--value')=='yes':
        run('systemctl','daemon-reload')
    detach(p,plan_sha)


def install(p, plan_sha):
    dest = Path(p['generation'])
    if dest.exists():
        verify(p, plan_sha)
        return
    # Never adopt incomplete resources. A journal is retained on interruption;
    # an operator must investigate it rather than blindly allocate again.
    dest.mkdir(mode=0o710)
    dest.chmod(0o710)
    os.chown(dest, 0, p['gid'])
    sync_directory(dest.parent)
    write_new(dest / 'pending.json', encoded({'version':1, 'planSha256':plan_sha}))
    old = protected(p['currentConfig']['path']).read_bytes()
    require(hashlib.sha256(old).hexdigest() == p['currentConfig']['sha256'], 'old config drift')
    config_delta(p,old,protected(p['newConfig']['path']).read_bytes())
    write_new(dest/'previous.env',old)
    oldunit=protected(p['unit']['path']).read_bytes()
    require(hashlib.sha256(oldunit).hexdigest()==p['unit']['sha256'],'old unit drift')
    unit_delta(p,oldunit,protected(p['newUnit']['path']).read_bytes())
    write_new(dest/'previous.service',oldunit)
    for name in ('runner', 'runsc', 'image'):
        with protected(p[name]['path']).open('rb') as src:
            fd = os.open(dest / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440 if name == 'image' else 0o550)
            with os.fdopen(fd, 'wb') as dst:
                shutil.copyfileobj(src, dst)
                dst.flush()
                os.fsync(dst.fileno())
        os.chown(dest / name, 0, p['gid'])
        (dest/name).chmod(0o440 if name=='image' else 0o550)
        fingerprint(dest / name, p[name]['sha256'], name != 'image')
    (dest / 'rootfs').mkdir(mode=0o710)
    (dest / 'rootfs').chmod(0o710)
    os.chown(dest / 'rootfs', 0, p['gid'])
    loop = run('losetup', '--find', '--show', '--read-only', str(dest / 'image'))
    require(re.fullmatch('/dev/loop[0-9]+', loop), 'allocated loop name')
    write_new(dest / 'allocated.json', encoded({'loop':loop, 'image':fingerprint(dest / 'image')}))
    verify_mapping(loop, dest / 'image')
    os.mknod(dest / 'loop', stat.S_IFBLK | 0o440, Path(loop).stat().st_rdev)
    (dest/'loop').chmod(0o440)
    os.chown(dest / 'loop', 0, p['gid'])
    run('mount', '-t', 'squashfs', '-o', 'ro,nosuid,nodev', loop, str(dest / 'rootfs'))
    state = {'version':1, 'planSha256':plan_sha, 'loop':loop,
             'objects':{name:fingerprint(dest / name) for name in ('runner','runsc','image')}}
    write_new(dest / 'state.json', encoded(state))
    verify(p, plan_sha, allow_pending=True)
    (dest / 'pending.json').unlink()
    sync_directory(dest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'verify', 'select', 'rollback', 'recover'])
    for name in ('plan', 'plan-sha256', 'drain', 'drain-sha256'):
        parser.add_argument('--'+name, required=True)
    a = parser.parse_args()
    require(os.geteuid() == 0, 'root required')
    os.environ['PATH']='/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL']='C'
    for name in ('LD_PRELOAD','LD_AUDIT','LD_LIBRARY_PATH'):
        os.environ.pop(name,None)
    p = load_plan(a.plan, a.plan_sha256)
    # One coordinator per generation parent, without adopting a foreign lock.
    parent = protected(Path(p['generation']).parent, True)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
        drained(p,a.plan_sha256,a.drain,a.drain_sha256)
        legacy(p)
        drained(p,a.plan_sha256,a.drain,a.drain_sha256)
        if a.action == 'recover':
            fingerprint(p['currentConfig']['path'],p['currentConfig']['sha256'])
            detach(p,a.plan_sha256,True)
        else:
            globals()[a.action](p,a.plan_sha256)
        print(json.dumps({'version':1,'action':a.action,'planSha256':a.plan_sha256,'serviceStarted':False}))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except (Refusal, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('refusing: runtime generation prerequisites or identities invalid', file=sys.stderr)
        sys.exit(1)
