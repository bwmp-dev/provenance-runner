import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('prepare_catalog', Path(__file__).with_name('prepare-paper-catalog.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PreparationTests(unittest.TestCase):
    def archive(self, path, entries):
        with tarfile.open(path, 'w') as archive:
            for name, target in entries:
                item = tarfile.TarInfo(name)
                item.mode = 0o755
                if target is not None:
                    item.type = tarfile.SYMTYPE
                    item.linkname = target
                    archive.addfile(item)
                else:
                    content = b'trusted fixture bytes'
                    item.size = len(content)
                    archive.addfile(item, io.BytesIO(content))

    def test_extraction_bounds_and_links(self):
        for entries in [[('../escape', None)], [('/absolute', None)], [('jdk/link', '../../escape')],
                        [('jdk/link', '/etc/passwd')], [('jdk/link', 'target'), ('jdk/link/file', None)],
                        [('jdk/file', None), ('jdk/file', None)], [('jdk/a', 'b'), ('jdk/b', 'a')]]:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.archive(root / 'java.tar', entries)
                (root / 'out').mkdir()
                with self.assertRaises((module.Invalid, RuntimeError)):
                    module.extract_java(root / 'java.tar', root / 'out', 1000)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.archive(root / 'java.tar', [('jdk/bin/java', None), ('jdk/bin/alias', 'java')])
            (root / 'out').mkdir()
            module.extract_java(root / 'java.tar', root / 'out', 1000)
            self.assertEqual((root / 'out/jdk/bin/alias').read_bytes(), b'trusted fixture bytes')
            (root / 'small').mkdir()
            with self.assertRaises(module.Invalid):
                module.extract_java(root / 'java.tar', root / 'small', 1)

    def fixture(self, root):
        self.archive(root / 'java.tar', [('jdk/bin/java', None)])
        (root / 'paper.jar').write_bytes(b'paper')
        def pin(path):
            data = path.read_bytes()
            return {'sha256': hashlib.sha256(data).hexdigest(), 'sizeBytes': len(data)}
        catalog = {'java': {'artifact': pin(root / 'java.tar'), 'archiveRoot': 'jdk', 'maximumExpandedBytes': 10000}, 'paper': {'artifact': pin(root / 'paper.jar')}}
        (root / 'catalog.json').write_text(json.dumps(catalog))
        tool = root / 'tool'
        tool.write_text('#!/usr/bin/env python3\nimport sys,pathlib\nargs=sys.argv[1:]\npathlib.Path(args[args.index("-output")+1]).write_bytes(b"prepared")\n')
        tool.chmod(0o755)
        return argparse.Namespace(catalog=str(root / 'catalog.json'), java_archive=str(root / 'java.tar'), paper=str(root / 'paper.jar'), runtime_tool=str(tool), runtime_uri='https://assets.example.invalid/runtime?private=fixture', output_dir=str(root / 'output'), maximum_prepared_bytes=10000)

    def test_full_output_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            module.prepare(args)
            output = json.loads((root / 'output/catalog.json').read_text())
            self.assertEqual(output['preparedRuntime']['artifact']['sha256'], hashlib.sha256(b'prepared').hexdigest())
            self.assertEqual((root / 'output/catalog.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                module.prepare(args)
            self.assertEqual((root / 'output/paper-runtime.tar.gz').read_bytes(), b'prepared')

    def test_bad_pin_or_subprocess_failure_cleans_outputs(self):
        for failure in ('paper-hash', 'java-hash', 'tool'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = self.fixture(root)
                if failure == 'paper-hash':
                    (root / 'paper.jar').write_bytes(b'xxxxx')
                elif failure == 'java-hash':
                    (root / 'java.tar').write_bytes(b'changed')
                else:
                    (root / 'tool').write_text('#!/bin/sh\nexit 1\n')
                with self.assertRaises(Exception):
                    module.prepare(args)
                self.assertFalse((root / 'output').exists())
