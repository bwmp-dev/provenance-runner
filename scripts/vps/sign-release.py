#!/usr/bin/env python3
"""Sign a hosted runner binary manifest on the trusted release machine."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from updater import signing_bytes

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--version', required=True, help='Must equal the compiled runner buildinfo.Version')
p.add_argument('--url', required=True, help='Direct immutable HTTPS URL without redirects')
p.add_argument('--private-key', type=Path, required=True, help='Offline Ed25519 PEM key; never copy to a runner')
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
with a.binary.open('rb') as f:
    digest = hashlib.file_digest(f, 'sha256').hexdigest()
r = {'version': a.version, 'url': a.url, 'sha256': digest, 'sizeBytes': a.binary.stat().st_size, 'signature': ''}
with tempfile.TemporaryDirectory() as temp:
    message, signature = Path(temp)/'message', Path(temp)/'signature'
    message.write_bytes(signing_bytes(r))
    subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(a.private_key), '-in', str(message), '-out', str(signature)], check=True)
    r['signature'] = base64.b64encode(signature.read_bytes()).decode()
with a.output.open('x') as f:
    json.dump(r, f, indent=2)
    f.write('\n')
