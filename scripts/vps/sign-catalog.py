#!/usr/bin/env python3
"""Canonicalize and sign an approved hosted Paper catalog revision offline."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit

from updater import catalog_signing_bytes, unique

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--catalogs', type=Path, required=True, help='Approved strict Paper catalog JSON array')
parser.add_argument('--api-origin', required=True, help='Backend origin that serves credential-scoped immutable assets')
parser.add_argument('--private-key', type=Path, required=True, help='Offline Ed25519 PEM key; never copy to a runner or API host')
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()

catalogs = json.loads(args.catalogs.read_bytes(), object_pairs_hook=unique)
origin = urlsplit(args.api_origin)
if origin.scheme != 'https' or not origin.hostname or origin.path or origin.query or origin.fragment or origin.username:
    raise ValueError('API origin must be an HTTPS origin')
for catalog in catalogs:
    for asset in (catalog['paper']['artifact'], catalog['java']['artifact'], catalog['probe'], catalog['preparedRuntime']['artifact']):
        asset['uri'] = args.api_origin+'/v1/runner-catalog-assets/'+asset['sha256']+'/'+asset['filename']
payload = {'schemaVersion':'provenance.hosted-paper-catalog/v1', 'artifactHosts':[origin.hostname], 'catalogs':catalogs}
canonical = json.dumps(payload, separators=(',', ':'), ensure_ascii=False, sort_keys=True).encode()
revision = dict(payload, sha256=hashlib.sha256(canonical).hexdigest(), signature='')
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    (root/'message').write_bytes(catalog_signing_bytes(revision))
    subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(args.private_key),
                    '-in', str(root/'message'), '-out', str(root/'signature')], check=True)
    revision['signature'] = base64.b64encode((root/'signature').read_bytes()).decode()
with args.output.open('x') as output:
    json.dump(revision, output, indent=2, ensure_ascii=False)
    output.write('\n')
