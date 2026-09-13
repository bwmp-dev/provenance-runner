"""Extract only frozen vectors from the independently verified alpha.30 release."""
import hashlib
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_SHA256 = "9d29bbb9345f8840765b0d327f1fd2a9bb371503cc4da50534473057c65c97c6"
VECTOR_SHA256 = "16118081708038af0b324444a3ecab8cbc6b07e6e681b510fe50a6558293c1ca"
MEMBER = "provenance-runner-protocol-0.1.0-alpha.30/proto/network-policy-v2/vectors.json"


def main():
    if len(sys.argv) != 2:
        raise SystemExit("verified alpha.30 runner archive required")
    source = Path(sys.argv[1])
    if hashlib.sha256(source.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise SystemExit("released archive digest mismatch")
    with tarfile.open(source, "r:gz") as archive:
        names = [member.name for member in archive.getmembers()]
        if len(names) != len(set(names)):
            raise SystemExit("duplicate archive member")
        member = archive.getmember(MEMBER)
        if not member.isfile() or member.size > 65536:
            raise SystemExit("invalid vector member")
        raw = archive.extractfile(member).read()
    if hashlib.sha256(raw).hexdigest() != VECTOR_SHA256:
        raise SystemExit("released vector digest mismatch")
    target = ROOT / "internal/networkpolicy/testdata/released-v2-vectors.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    print(VECTOR_SHA256)


if __name__ == "__main__":
    main()
