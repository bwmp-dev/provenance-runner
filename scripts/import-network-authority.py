"""Copy verified released authority semantics/vectors, without archive execution."""
import hashlib
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SHA256 = "0fb88e5ee81b152f9592206fe5d4fd2f05b76896e64506cf840b899e2724e851"
PREFIX = "provenance-runner-protocol-0.1.0-alpha.34/proto/network-authority-v2/"

if len(sys.argv) != 2:
    raise SystemExit("verified alpha34 runner archive required")
source = Path(sys.argv[1])
if hashlib.sha256(source.read_bytes()).hexdigest() != SHA256:
    raise SystemExit("released archive digest mismatch")
outputs = {}
with tarfile.open(source, "r:gz") as archive:
    names = [item.name for item in archive.getmembers()]
    if len(names) != len(set(names)):
        raise SystemExit("duplicate archive member")
    for name, target in {
        "vectors.json": "internal/networkpolicy/testdata/authority-v2-vectors.json",
        "semantics.md": "docs/released-network-authority-v2.md",
    }.items():
        member = archive.getmember(PREFIX + name)
        if not member.isfile() or member.size > 1 << 20:
            raise SystemExit("invalid contract member")
        outputs[target] = archive.extractfile(member).read()
for target, data in outputs.items():
    (ROOT / target).write_bytes(data)
    print(target, hashlib.sha256(data).hexdigest())
