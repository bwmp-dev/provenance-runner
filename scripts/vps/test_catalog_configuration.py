"""Stopped-node catalog transaction tests; never invoke root or real services."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_install import i, settings, catalog_settings


class CatalogConfigurationTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, failure=None):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            root = Path(directory) / 'root'
            root.mkdir()
            state = Path(directory) / 'state'
            state.mkdir()
            original = settings()
            (root / 'settings.json').write_text(json.dumps(original))
            (root / 'runner.env').write_text('LEGACY=unchanged\n')
            (root / 'runner').write_bytes(b'accepted runner executable')
            (root / 'installed.json').write_text(json.dumps({'runnerSha256': hashlib.sha256(b'accepted runner executable').hexdigest()}))
            catalogs = Path(directory) / 'catalogs.json'
            catalogs.write_text(json.dumps(catalog_settings()['paperCatalogs']))
            payload = b'verified fixture archive'
            digest = hashlib.sha256(payload).hexdigest()
            asset = {'uri': 'https://assets.example.com/private', 'sizeBytes': len(payload), 'sha256': digest}
            calls, transfers = [], []
            account = SimpleNamespace(pw_uid=12345, pw_gid=12345)
            def run(*args, **kwargs):
                calls.append(args)
                if args[0] == str(root / 'runner'):
                    self.assertEqual(args[1], 'validate-paper-catalogs')
                    if failure == 'old-binary':
                        raise ValueError('unsupported command')
                elif args[0] == 'curl':
                    Path(args[args.index('--output') + 1]).write_bytes(b'x' * len(payload) if failure == 'hash' else payload)
                else:
                    self.fail('unexpected privileged command')
            def as_user(actual, *args, **kwargs):
                self.assertIs(actual, account)
                calls.append(('as-user', *args))
                if args[:2] == ('systemctl', '--user'):
                    return 'ActiveState=inactive\n'
                self.assertEqual(args[:2], ('mkdir', '-p'))
                Path(args[2]).mkdir(parents=True, exist_ok=True)
            def transfer(args, **kwargs):
                self.assertEqual(args[:6], ['runuser', '-u', i.USER, '--', 'python3', '-I'])
                self.assertNotIn('shell', kwargs)
                content = kwargs['stdin'].read()
                transfers.append((args, content))
                Path(args[-1]).write_bytes(content)
                return SimpleNamespace(returncode=0)
            temporary_class = tempfile.TemporaryDirectory
            def private_temporary(*args, **kwargs):
                self.assertEqual(kwargs.pop('dir'), '/root')
                return temporary_class(*args, dir=directory, **kwargs)
            real_replace = i.os.replace
            replacements = []
            def replace(source, destination):
                replacements.append(Path(destination).name)
                if failure in ('replace', 'rollback') and Path(destination).name == 'runner.env':
                    raise OSError('replacement failed')
                return real_replace(source, destination)
            real_copyfile = i.shutil.copyfile
            def copyfile(source, destination, *args, **kwargs):
                if failure == 'rollback' and Path(source).parent.name.startswith('catalog-backup-') and Path(destination).name == 'settings.json':
                    raise OSError('rollback interrupted')
                return real_copyfile(source, destination, *args, **kwargs)
            for target, value in [('ROOT', root), ('STATE', state)]:
                stack.enter_context(patch.object(i, target, value))
            stack.enter_context(patch.object(i, 'protected'))
            stack.enter_context(patch.object(i.pwd, 'getpwnam', return_value=account))
            stack.enter_context(patch.object(i, 'run', side_effect=run))
            stack.enter_context(patch.object(i, 'as_user', side_effect=as_user))
            stack.enter_context(patch.object(i, 'assets_for_settings', return_value=[(digest, asset)]))
            stack.enter_context(patch.object(i.tempfile, 'TemporaryDirectory', side_effect=private_temporary))
            stack.enter_context(patch.object(i.subprocess, 'run', side_effect=transfer))
            stack.enter_context(patch.object(i.os, 'chown'))
            stack.enter_context(patch.object(i.os, 'replace', side_effect=replace))
            stack.enter_context(patch.object(i.shutil, 'copyfile', side_effect=copyfile))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            yield SimpleNamespace(root=root, state=state, catalogs=catalogs, original=original, calls=calls, transfers=transfers, digest=digest, payload=payload)

    def test_old_binary_refused_before_download_or_configuration_write(self):
        with self.fixture('old-binary') as f:
            with self.assertRaises(ValueError):
                i.configure_catalogs(f.catalogs)
            self.assertFalse(any(call[0] == 'curl' for call in f.calls))
            self.assertEqual(json.loads((f.root / 'settings.json').read_text()), f.original)
            self.assertEqual((f.root / 'runner.env').read_text(), 'LEGACY=unchanged\n')
            self.assertFalse((f.root / 'INSTALLING').exists())
            self.assertEqual(f.transfers, [])

    def test_hash_failure_preserves_settings_and_cache(self):
        with self.fixture('hash') as f:
            with self.assertRaisesRegex(ValueError, 'integrity'):
                i.configure_catalogs(f.catalogs)
            self.assertEqual(json.loads((f.root / 'settings.json').read_text()), f.original)
            self.assertEqual((f.root / 'runner.env').read_text(), 'LEGACY=unchanged\n')
            self.assertFalse((f.root / 'INSTALLING').exists())
            self.assertEqual(f.transfers, [])

    def test_success_transfers_as_worker_and_replaces_both_files(self):
        with self.fixture() as f:
            i.configure_catalogs(f.catalogs)
            updated = json.loads((f.root / 'settings.json').read_text())
            self.assertEqual(updated['runnerId'], f.original['runnerId'])
            self.assertEqual(updated['platformCredentialFile'], f.original['platformCredentialFile'])
            self.assertNotIn('probe', updated)
            self.assertNotIn('preparedRuntime', updated)
            self.assertEqual(updated['paperCatalogs'], json.loads(f.catalogs.read_text()))
            self.assertIn('PROVENANCE_PAPER_CATALOGS_JSON=', (f.root / 'runner.env').read_text())
            self.assertNotIn('PROVENANCE_PAPER_PREPARED_RUNTIME_URI=', (f.root / 'runner.env').read_text())
            self.assertEqual(len(f.transfers), 1)
            self.assertEqual(f.transfers[0][1], f.payload)
            self.assertEqual(Path(f.transfers[0][0][-1]), f.state / 'cache/content/sha256' / f.digest[:2] / f.digest[2:])
            self.assertFalse((f.root / 'INSTALLING').exists())
            self.assertEqual((f.root / 'settings.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual((f.root / 'runner.env').stat().st_mode & 0o777, 0o640)
            self.assertFalse(any('start' in call or 'restart' in call for call in f.calls))

    def test_replacement_failure_restores_original_files(self):
        with self.fixture('replace') as f:
            with self.assertRaises(OSError):
                i.configure_catalogs(f.catalogs)
            self.assertEqual(json.loads((f.root / 'settings.json').read_text()), f.original)
            self.assertEqual((f.root / 'runner.env').read_text(), 'LEGACY=unchanged\n')
            self.assertFalse((f.root / 'INSTALLING').exists())
            self.assertEqual(len(list(f.root.glob('catalog-backup-*'))), 1)

    def test_failed_rollback_retains_marker_to_block_activation(self):
        with self.fixture('rollback') as f:
            with self.assertRaises(OSError):
                i.configure_catalogs(f.catalogs)
            self.assertTrue((f.root / 'INSTALLING').is_file())
            self.assertEqual(len(list(f.root.glob('catalog-backup-*'))), 1)
