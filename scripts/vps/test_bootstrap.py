import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('bootstrap', Path(__file__).with_name('bootstrap-hosted.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

class BundleSafety(unittest.TestCase):
    def archive(self, root, names, link=False):
        path = root/'bundle.tar.gz'
        with tarfile.open(path, 'w:gz') as tar:
            for name in names:
                member = tarfile.TarInfo(name)
                member.size = 1
                if link:
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/etc/shadow'
                tar.addfile(member, io.BytesIO(b'x'))
        return path

    def test_complete_flat_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root/'out'; target.mkdir()
            b.extract(self.archive(root, b.FILES), target)
            self.assertEqual({p.name for p in target.iterdir()}, b.FILES)
            self.assertEqual((target/'install.py').stat().st_mode & 0o777, 0o600)

    def test_archive_attacks_and_incomplete_bundles(self):
        for names, link in [(['../install.py'], False), (['/etc/shadow'], False), (['install.py'], True),
                            (['install.py', 'install.py'], False), (['install.py'], False),
                            (['runner-bundle/../../install.py'], False)]:
            with self.subTest(names=names, link=link), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); target = root/'out'; target.mkdir()
                with self.assertRaises(ValueError):
                    b.extract(self.archive(root, names, link), target)

    def test_duplicate_json_refused(self):
        with self.assertRaises(ValueError):
            b.unique([('credential', 'one'), ('credential', 'two')])

    def test_redirect_refused(self):
        with self.assertRaises(ValueError):
            b.NoRedirect().redirect_request(None)

class ManifestSafety(unittest.TestCase):
    def valid(self):
        import base64
        return {'schemaVersion':'provenance.hosted-install/v1','runnerId':'10000000-0000-4000-8000-000000000001',
                'credential':'phc_v1_'+base64.urlsafe_b64encode(b'x'*32).decode().rstrip('='),'updaterCredential':'pru_'+'a'*64,
                'profile':{'gatewayAddress':'gateway.example:443','apiOrigin':'https://api.example','artifactHosts':['assets.example'],
                           'probe':{},'preparedRuntime':{},'resources':{},'releasePublicKey':base64.b64encode(b'x'*32).decode(),
                           'bundle':{'uri':'https://assets.example/bundle','sha256':'a'*64,'sizeBytes':100}}}

    def test_valid_manifest_and_exact_credential_bytes(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('installer_exact', Path(__file__).with_name('install.py'))
        installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)
        data = self.valid()
        self.assertEqual(b.validate(data), data)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            b.private(root/'credential', data['credential'], newline=False)
            self.assertEqual((root/'credential').read_bytes(), data['credential'].encode())
            # Exercise the exact installer read/normalization/write chain, including manual newlines.
            for index, suffix in enumerate(('', '\n', '\r\n')):
                installer.write(root/str(index), installer.connection_credential(data['credential']+suffix))
                self.assertEqual((root/str(index)).read_bytes(), data['credential'].encode())

    def test_invalid_manifests(self):
        mutations = [lambda d:d.update(extra=True),lambda d:d.pop('runnerId'),lambda d:d.update(schemaVersion='unknown'),
                     lambda d:d.update(runnerId='not-a-uuid'),lambda d:d.update(credential=d['credential']+'x'),
                     lambda d:d.update(credential=d['credential'][:-1]+'B'),lambda d:d.update(updaterCredential='pru_no'),
                     lambda d:d['profile'].update(extra=True),lambda d:d['profile']['bundle'].update(sizeBytes=513*1024**2),
                     lambda d:d['profile'].update(releasePublicKey='eA==')]
        for mutation in mutations:
            data = self.valid();mutation(data)
            with self.subTest(data_keys=list(data)),self.assertRaises((ValueError,TypeError)):
                b.validate(data)
        for url in ('http://assets.example/bundle','https://other.example/bundle','https://user:pass@assets.example/bundle',
                    'https://assets.example:444/bundle','https://assets.example/bundle#fragment'):
            data=self.valid();data['profile']['bundle']['uri']=url
            with self.subTest(url=url),self.assertRaises(ValueError):b.validate(data)

    def test_download_enforces_size_and_hash(self):
        import hashlib
        from unittest.mock import patch
        class Response(io.BytesIO): status=200
        class Opener:
            def __init__(self,payload):self.payload=payload
            def open(self,*args,**kwargs):return Response(self.payload)
        for payload,expected,sha,valid in [(b'ok',2,hashlib.sha256(b'ok').hexdigest(),True),(b'too many',2,'a'*64,False),(b'ok',2,'a'*64,False),(b'x',2,'a'*64,False)]:
            with tempfile.TemporaryDirectory() as tmp,patch.object(b.urllib.request,'build_opener',return_value=Opener(payload)):
                asset={'uri':'https://assets.example/bundle','sizeBytes':expected,'sha256':sha}
                if valid:b.download(asset,Path(tmp)/'asset')
                else:
                    with self.assertRaises(ValueError):b.download(asset,Path(tmp)/'asset')

if __name__ == '__main__':
    unittest.main()
