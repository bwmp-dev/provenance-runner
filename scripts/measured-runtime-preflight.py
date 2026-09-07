#!/usr/bin/env python3
"""Safe scalar prerequisite diagnostics inside the disposable driver's scope."""
import ctypes
import errno
import json
import os
import re
from pathlib import Path
import subprocess


def scalar(path):
    try:
        value = Path(path).read_text()[:64].strip()
        return int(value) if value.isascii() and value.isdecimal() and len(value) <= 12 else None
    except OSError:
        return None


def confinement():
    try:
        return "unconfined" if Path("/proc/self/attr/current").read_text().strip() == "unconfined" else "confined"
    except OSError:
        return "unavailable"


def main():
    uid = os.getuid()
    if uid == 0:
        raise SystemExit("nonroot disposable diagnostic required")
    record = {"version": 1, "uid": uid,
              "unprivilegedUsernsClone": scalar("/proc/sys/kernel/unprivileged_userns_clone"),
              "maxUserNamespaces": scalar("/proc/sys/user/max_user_namespaces"),
              "apparmorRestrictUnprivilegedUserns": scalar("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
              "confinement": confinement()}
    release = os.uname().release
    record["kernelRelease"] = release if re.fullmatch(r"[A-Za-z0-9._+\-]{1,128}", release) else "unavailable"
    try:
        flag = Path("/sys/module/apparmor/parameters/enabled").read_text().strip()
        record["apparmorEnabled"] = {"Y": True, "N": False}.get(flag)
    except OSError:
        record["apparmorEnabled"] = None
    try:
        result = subprocess.run(["systemctl", "show", f"user@{uid}.service", "--property=RestrictNamespaces", "--value"], capture_output=True, timeout=5, check=True)
        value = result.stdout.decode("ascii").strip()
        allowed = {"yes", "no", "true", "false", "cgroup", "ipc", "net", "mnt", "pid", "user", "uts"}
        record["restrictNamespaces"] = value if len(value) <= 128 and value and all(x.lstrip("~") in allowed for x in value.split()) else "unavailable"
    except (OSError, UnicodeError, subprocess.SubprocessError):
        record["restrictNamespaces"] = "unavailable"
    # Only this short-lived process enters new namespaces. No mount, UID map,
    # host policy, or existing process is modified.
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.unshare(ctypes.c_int(0x10000000 | 0x00020000))
    number = ctypes.get_errno() if result != 0 else 0
    allowed_errno = {0: "none", errno.EPERM: "permission", errno.EACCES: "access", errno.EINVAL: "invalid", errno.ENOSYS: "unsupported", errno.ENOSPC: "capacity", errno.EAGAIN: "resources", errno.EUSERS: "users"}
    record["namespaceProbe"] = allowed_errno.get(number, "other")
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
