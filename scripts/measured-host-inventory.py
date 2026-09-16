#!/usr/bin/env python3
"""Read-only candidate identity/storage inventory; never authorizes activation."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

LIMIT = 1 << 20
MAX_ID = (1 << 32) - 2


def bounded(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        assert stat.S_ISREG(os.fstat(source.fileno()).st_mode)
        raw = source.read(LIMIT + 1)
    assert len(raw) <= LIMIT
    return raw.decode('ascii')


def ranges(raw, subordinate):
    result = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        fields = line.split(':') if subordinate else line.split()
        assert len(fields) == 3
        if subordinate:
            assert fields[0] and len(fields[0]) <= 256
            start, count = fields[1:]
        else:
            assert fields[0].isdigit()
            start, count = fields[1:]
        assert start.isdigit() and count.isdigit()
        start, count = int(start), int(count)
        assert 0 <= start <= MAX_ID and 0 < count <= MAX_ID + 1 and start + count <= MAX_ID + 1
        result.append((start, start + count))
    return result


def conflicts(selected, allocations):
    return sorted(value for value in selected if any(start <= value < end for start, end in allocations))


def account_ids(raw, group):
    result = set()
    for line in raw.splitlines():
        fields = line.split(':')
        assert len(fields) == (4 if group else 7) and fields[2].isdigit()
        value = int(fields[2])
        assert 0 <= value <= MAX_ID
        result.add(value)
        if not group:
            assert fields[3].isdigit() and 0 <= int(fields[3]) <= MAX_ID
            result.add(int(fields[3]))
    return result


def process_ids(raw):
    selected = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(':')
        if separator and key in ('Uid', 'Gid', 'Groups'):
            assert key not in selected
            fields = value.split()
            assert all(field.isdigit() for field in fields)
            assert (len(fields) == 4) if key != 'Groups' else (len(fields) <= 65536)
            values = {int(field) for field in fields}
            assert all(0 <= field <= MAX_ID for field in values)
            selected[key] = values
    assert set(selected) == {'Uid', 'Gid', 'Groups'}
    return selected['Uid'], selected['Gid'] | selected['Groups']


def get_accounts(group):
    result = subprocess.run(['/usr/bin/getent', 'group' if group else 'passwd'],
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'},
                            capture_output=True, check=True, timeout=5)
    assert len(result.stdout) <= LIMIT and len(result.stderr) <= LIMIT
    return account_ids(result.stdout.decode('ascii'), group)


def inventory(selected, worker_uid, storage):
    assert os.geteuid() == 0 and Path('/proc/1/status').is_file()
    assert len(selected) == 2 and all(65536 <= value <= MAX_ID for value in selected) and worker_uid not in selected
    assert 0 < worker_uid <= MAX_ID
    assert storage.is_absolute() and storage.resolve(strict=True) == storage and storage.is_dir()
    start = time.monotonic()
    uid_ranges, gid_ranges = ranges(bounded('/etc/subuid'), True), ranges(bounded('/etc/subgid'), True)
    users, groups = get_accounts(False), get_accounts(True)
    initial_namespace = os.stat('/proc/1/ns/user').st_ino
    process_conflicts, mapped_conflicts = set(), set()
    namespaces, processes, vanished = set(), 0, 0
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        assert time.monotonic() - start < 30 and processes < 32768
        processes += 1
        try:
            uids, gids = process_ids(bounded(entry/'status'))
            process_conflicts.update(selected & (uids | gids))
            namespace = os.stat(entry/'ns/user').st_ino
            if namespace != initial_namespace and namespace not in namespaces:
                namespaces.add(namespace)
                mapped_conflicts.update(conflicts(selected, ranges(bounded(entry/'uid_map'), False)))
                mapped_conflicts.update(conflicts(selected, ranges(bounded(entry/'gid_map'), False)))
        except (FileNotFoundError, ProcessLookupError):
            vanished += 1
    filesystem = os.statvfs(storage)
    boot = bounded('/proc/sys/kernel/random/boot_id').strip()
    assert re.fullmatch('[a-f0-9-]{36}', boot)
    return {
        'format': 1, 'observedAt': datetime.now(timezone.utc).isoformat(), 'bootId': boot,
        'candidateIds': sorted(selected), 'workerUid': worker_uid,
        'accountConflicts': sorted(selected & (users | groups)),
        'subordinateUidConflicts': conflicts(selected, uid_ranges),
        'subordinateGidConflicts': conflicts(selected, gid_ranges),
        'processCredentialConflicts': sorted(process_conflicts),
        'namespaceMappingConflicts': sorted(mapped_conflicts),
        'observedProcesses': processes, 'otherUserNamespaces': len(namespaces), 'vanishedProcesses': vanished,
        'storageAvailableBytes': filesystem.f_bavail * filesystem.f_frsize,
        'storageReadOnly': bool(filesystem.f_flag & os.ST_RDONLY),
        'identityReservationPerformed': False, 'filesystemOwnershipScanPerformed': False,
        'persistentDiskBoundConfirmed': False, 'readyForActivation': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workload-id', type=int, required=True)
    parser.add_argument('--router-id', type=int, required=True)
    parser.add_argument('--worker-uid', type=int, required=True)
    parser.add_argument('--storage-parent', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = inventory({args.workload_id, args.router_id}, args.worker_uid, args.storage_parent)
    except Exception:
        raise SystemExit('Measured host inventory incomplete; no activation or provisioning performed.') from None
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
