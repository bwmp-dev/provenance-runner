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
