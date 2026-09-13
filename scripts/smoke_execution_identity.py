"""Allocate independent evidence identities for redelivered CI executions."""
import json
import re
import sys
import uuid


def allocate(candidate, run, attempt):
    if not re.fullmatch(r"[0-9a-f]{40}", candidate):
        raise ValueError("exact source identity required")
    if any(not re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run, attempt)):
        raise ValueError("bounded positive workflow identifiers required")
    execution = uuid.uuid4().hex
    identity = f"{candidate}-{run}-{attempt}-{execution}"
    return {
        "execution": execution,
        "artifact": "systemd-user-smoke-" + identity,
        "remoteDirectory": "/var/lib/provenance-plan0506/ci-smoke/" + identity,
        "scope": f"provenance-ci-{run}-{attempt}-{execution}",
    }


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("three identifiers required")
        print(json.dumps(allocate(*sys.argv[1:])))
    except ValueError:
        raise SystemExit("invalid smoke execution identity") from None
