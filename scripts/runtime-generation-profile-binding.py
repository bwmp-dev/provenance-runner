#!/usr/bin/env python3
"""Bind the guest to the existing exclusive CI attachment; never load policy."""
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys


def identity(path, gid):
    assert re.fullmatch(r'/var/lib/provenance-measurement-ci\.[A-Za-z0-9]{8}/gvisor-smoke.test', str(path))
    for parent in path.parents:
        s = parent.lstat()
        assert stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and s.st_mode & 0o022 == 0
    s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1
    assert s.st_uid == 0 and s.st_gid == gid and stat.S_IMODE(s.st_mode) == 0o550
    with path.open('rb') as f:
        assert f.read(4) == b'\x7fELF'
        f.seek(0)
        digest = hashlib.file_digest(f, 'sha256').hexdigest()
        after = os.fstat(f.fileno())
    assert (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    return dict(path=str(path), device=s.st_dev, inode=s.st_ino, sha256=digest,
                owner=s.st_uid, group=s.st_gid, mode=stat.S_IMODE(s.st_mode))


def main():
    action, raw_path, raw_uid, raw_gid, raw_record = sys.argv[1:]
    assert action in ('record', 'verify', 'container') and os.geteuid() == 0
    path, uid, gid, record = Path(raw_path), int(raw_uid), int(raw_gid), Path(raw_record)
    assert 60000 <= uid <= 63999 and gid > 0
    if action != 'container':
        assert grp.getgrgid(gid).gr_mem == []
        assert [p.pw_uid for p in pwd.getpwall() if p.pw_gid == gid] == [uid]
        s = path.parent.lstat()
        assert s.st_gid == gid and stat.S_IMODE(s.st_mode) == 0o710
    value = dict(version=1, uid=uid, gid=gid, executable=identity(path, gid))
    if action == 'record':
        fd = os.open(record, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f, sort_keys=True)
            f.write('\n')
    else:
        assert json.loads(record.read_text()) == value, 'profile attachment identity drifted'
    print(json.dumps(dict(profileAttachmentBinding=action, **value), sort_keys=True))


if __name__ == '__main__':
    main()
