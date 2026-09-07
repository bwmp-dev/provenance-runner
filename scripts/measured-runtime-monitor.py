#!/usr/bin/env python3
"""Bounded observation, not exhaustive detection of short-lived executables."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time


def scope_matches(value, root):
    return any(line.startswith("0::" + root + "/") and
               re.fullmatch(r"[^/]+\.scope(?:/[^\n]*)?", line[len("0::" + root + "/"):])
               for line in value.splitlines())


def identity(fd):
    s = os.fstat(fd)
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def inspect(pid, uid, root, expected, proc=Path("/proc")):
    p = proc / str(pid)
    # Never retain arguments or environment. Read argv[0] only, with a fixed bound.
    if p.stat().st_uid != uid:
        return None
    with (p / "cmdline").open("rb") as f:
        name = f.read(64).split(b"\0", 1)[0]
    if name not in (b"runsc-sandbox", b"runsc-gofer"):
        return None
    before = (p / "stat").read_text().rsplit(")", 1)[1].split()[19]
    if not scope_matches((p / "cgroup").read_text(), root):
        return None
    fd = os.open(p / "exe", os.O_RDONLY | os.O_CLOEXEC)
    try:
        first = identity(fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode) or not 0 < first[2] <= 256 << 20:
            raise ValueError("invalid observed executable")
        with os.fdopen(os.dup(fd), "rb") as f:
            digest = hashlib.file_digest(f, "sha256").hexdigest()
        if first != identity(fd):
            raise ValueError("observed executable changed")
        # Revalidate ownership, scope, process start and current executable after hashing.
        if p.stat().st_uid != uid or before != (p / "stat").read_text().rsplit(")", 1)[1].split()[19]:
            return None
        if not scope_matches((p / "cgroup").read_text(), root):
            return None
        if (p / "exe").stat().st_ino != first[1] or (p / "exe").stat().st_dev != first[0]:
            return None
        if first[:3] != expected[:3] or digest != expected[3]:
            raise ValueError("observed executable does not match retained frontend")
        return {"pid": pid, "startTicks": before, "role": name.decode(),
                "device": first[0], "inode": first[1], "bytes": first[2], "sha256": digest}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--scope-root", required=True)
    parser.add_argument("--frontend", required=True)
    parser.add_argument("--stop-file", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not 60000 <= args.uid < 64000 or args.scope_root != "/user.slice/user-%d.slice/user@%d.service/app.slice" % (args.uid, args.uid):
        raise ValueError("invalid fixture identity")
    records, seen, error = [], set(), None
    started = time.monotonic()
    with open(args.frontend, "rb") as f:
        s = os.fstat(f.fileno())
        initial = identity(f.fileno())
        if not stat.S_ISREG(s.st_mode) or not 0 < s.st_size <= 256 << 20:
            raise ValueError("invalid retained frontend")
        expected = (s.st_dev, s.st_ino, s.st_size, hashlib.file_digest(f, "sha256").hexdigest())
        if identity(f.fileno()) != initial:
            raise ValueError("retained frontend changed")
        while time.monotonic() - started < 190 and not Path(args.stop_file).exists():
            for p in Path("/proc").iterdir():
                if not p.name.isdecimal():
                    continue
                try:
                    record = inspect(int(p.name), args.uid, args.scope_root, expected)
                    if record and (record["pid"], record["startTicks"], record["role"]) not in seen:
                        seen.add((record["pid"], record["startTicks"], record["role"]))
                        records.append(record)
                        if len(records) > 256:
                            raise ValueError("observation bound exceeded")
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except (OSError, ValueError) as exc:
                    error = type(exc).__name__
                    break
            if error:
                break
            time.sleep(0.02)
    roles = {r["role"] for r in records}
    passed = not error and roles == {"runsc-sandbox", "runsc-gofer"}
    with open(args.output, "x") as output:
        json.dump({"version": 1, "passed": passed, "error": error,
                   "pollingIsExhaustive": False, "observations": records,
                   "durationSeconds": time.monotonic() - started}, output, indent=2)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
