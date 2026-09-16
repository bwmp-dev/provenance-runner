#!/usr/bin/env python3
"""Compile trusted inert fixture sources; never execute a supplied JAR."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

API = 'aab18363ca5a1aaadd4e2716ee0de50bc26f352901af962177d86484baff7478'
KEY = 'd4f21f4281e89dab345a9004567668794819f9cc483eaff8bfd64c57494a9150'
INPUTS = {'java.tar.gz': '968c283e104059dae86ea1d670672a80170f27a39529d815843ec9c1f0fa2a03',
          'paper.jar': '8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e',
          'target.jar': 'a0c881f0a9e2229143ae8cfcc5fd019de02ce96504fe66c29f90eb13aad004ba',
          'prepared-runtime.tar.gz': 'bd8ba32e4ec988a09335b868a9585c94ca75600e445f37825fd8339bee45d69c'}

def digest(path):
    assert path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 256 << 20
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('api', 'key', 'inputs', 'output'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--javac', default='javac')
    args = parser.parse_args()
    assert digest(args.api) == API and digest(args.key) == KEY
    assert args.output.is_absolute() and args.output.resolve() == args.output and not args.output.exists()
    for name, expected in INPUTS.items():
        assert digest(args.inputs/name) == expected
    source = Path(__file__).resolve().parent/'secret-fixture'
    version = subprocess.check_output([args.javac, '-version'], text=True, timeout=10).strip()
    assert version == 'javac 21.0.12.1'
    with tempfile.TemporaryDirectory(prefix='provenance-secret-compile-', dir='/var/tmp') as temporary:
        work = Path(temporary)
        subprocess.run([args.javac, '-proc:none', '--release', '21', '-encoding', 'UTF-8', '-g:none',
                        '-classpath', str(args.api)+os.pathsep+str(args.key), '-d', str(work),
                        str(source/'SecretFixture.java')], check=True, timeout=30)
        args.output.mkdir(mode=0o700)
        for name, expected in INPUTS.items():
            with (args.inputs/name).open('rb') as src, (args.output/name).open('xb') as dst:
                shutil.copyfileobj(src, dst, 1 << 16)
            assert digest(args.output/name) == expected
            (args.output/name).chmod(0o444)
        target = args.output/'secret-target.jar'
        with zipfile.ZipFile(target, 'x', compression=zipfile.ZIP_STORED) as jar:
            for name, path in [('dev/provenance/fixtures/SecretFixture.class', work/'dev/provenance/fixtures/SecretFixture.class'), ('plugin.yml', source/'plugin.yml')]:
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = 0o100444 << 16
                jar.writestr(entry, path.read_bytes())
        target.chmod(0o444)
        print(json.dumps({'fixtureSHA256':digest(target), 'sizeBytes':target.stat().st_size,
                          'sourceSHA256':digest(source/'SecretFixture.java'), 'compiler':version,
                          'apiSHA256':API, 'keySHA256':KEY, 'executed':False}, sort_keys=True))

if __name__ == '__main__':
    main()
