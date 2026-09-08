import copy
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('installer', Path(__file__).with_name('install.py'))
i = importlib.util.module_from_spec(spec)
spec.loader.exec_module(i)


def settings():
    return {'gatewayAddress': 'gateway.example.com:443',
            'runnerId': '10000000-0000-0000-0000-000000000001',
            'platformCredentialFile': '/root/platform-runner-credential', 'artifactHosts': ['assets.example.com'],
            'probe': {'uri': 'https://assets.example.com/probe.jar', 'sha256': i.PROBE, 'sizeBytes': 478853},
            'preparedRuntime': {'uri': 'https://assets.example.com/runtime.tar.gz', 'sha256': 'a'*64,
                                'sizeBytes': 100, 'maximumExpandedBytes': 1000},
            'resources': {'cpuMillis': 1000, 'memoryBytes': 1024**3, 'diskBytes': 1024**3, 'processCount': 512}}


class Settings(unittest.TestCase):
    def test_platform_settings(self):
        value = settings()
        self.assertEqual(i.validate(value), value)

    def test_self_hosted_and_management_fields_refused(self):
        for field in ('organizationId', 'registrationTokenFile', 'apiOrigin', 'DATABASE_URL', 'managementToken'):
            value = settings()
            value[field] = 'private'
            with self.assertRaises(ValueError):
                i.validate(value)

    def test_bad_endpoint_vectors(self):
        for uri in ('http://assets.example.com/probe', 'https://x:y@assets.example.com/probe',
                    'https://assets.example.com/probe?token=private', 'https://assets.example.com/probe#x',
                    'https://other.example.com/probe', 'https://assets.example.com:444/probe',
                    'https://assets.example.com/"\nX=1', 'https://assets.example.com/$HOME'):
            value = settings()
            value['probe']['uri'] = uri
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                i.validate(value)

    def test_catalog_pin_and_bounds(self):
        for key, field, value in [('probe', 'sha256', '0'*64), ('probe', 'sizeBytes', 478837),
                                  ('preparedRuntime', 'sizeBytes', True), ('preparedRuntime', 'maximumExpandedBytes', 2**31),
                                  ('resources', 'cpuMillis', 0), ('resources', 'processCount', -1)]:
            obj = settings()
            obj[key][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                i.validate(obj)

    def test_json_duplicate_fields_refused(self):
        with self.assertRaises(ValueError):
            json.loads('{"probe":1,"probe":2}', object_pairs_hook=i.unique)

    def test_environment_has_only_runtime_inputs(self):
        account = type('Account', (), {'pw_uid': 1234})()
        env = i.environment(settings(), account)
        self.assertIn('PROVENANCE_GVISOR_CGROUP_DRIVER="systemd-user"', env)
        self.assertIn('user-1234.slice/user@1234.service/app.slice', env)
        self.assertNotIn('registration', env)
        self.assertNotIn('api.example', env)


class Archives(unittest.TestCase):
    def check(self, entries):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'rootfs.tar'
            with tarfile.open(path, 'w') as archive:
                for name, kind, target in entries:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = target
                    archive.addfile(member, io.BytesIO(b''))
            i.archive_check(path)

    def test_ordinary_files_and_guest_absolute_symlinks(self):
        self.check([('usr/bin/sh', tarfile.REGTYPE, ''), ('bin', tarfile.SYMTYPE, 'usr/bin'),
                    ('etc/mtab', tarfile.SYMTYPE, '/proc/mounts')])

    def test_no_write_through_symlink_in_either_order(self):
        entries = [('escape', tarfile.SYMTYPE, '/etc'), ('escape/passwd', tarfile.REGTYPE, '')]
        for items in (entries, list(reversed(entries))):
            with self.assertRaises(ValueError):
                self.check(items)

    def test_traversal_device_duplicate_and_hardlink(self):
        for entries in [[('../escape', tarfile.REGTYPE, '')], [('/etc/escape', tarfile.REGTYPE, '')],
                        [('dev/bad', tarfile.CHRTYPE, '')], [('a', tarfile.REGTYPE, ''), ('a', tarfile.REGTYPE, '')],
                        [('a', tarfile.LNKTYPE, '/etc/passwd')], [('a', tarfile.LNKTYPE, '../passwd')]]:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.check(entries)

    def test_internal_hardlink(self):
        self.check([('usr/bin/tool', tarfile.REGTYPE, ''), ('usr/bin/alias', tarfile.LNKTYPE, 'usr/bin/tool')])


class Failures(unittest.TestCase):
    def test_bad_settings_never_run_host_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'settings.json'
            p.write_text('{"DATABASE_URL":"must-not-be-used"}')
            with patch.object(i, 'protected'), patch.object(i, 'run') as command:
                with self.assertRaises(ValueError):
                    i.install(Path(tmp), p, False)
                command.assert_not_called()

    def test_command_error_does_not_expose_stderr_or_arguments(self):
        result = type('Result', (), {'returncode': 1, 'stderr': 'secret', 'stdout': 'secret'})()
        with patch.object(i.subprocess, 'run', return_value=result):
            with self.assertRaises(ValueError) as error:
                i.run('runner', 'secret')
        self.assertNotIn('secret', str(error.exception))

    def test_exclusive_write_preserves_existing_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'credential'
            p.write_text('original')
            with self.assertRaises(FileExistsError):
                i.write(p, 'replacement')
            self.assertEqual(p.read_text(), 'original')


if __name__ == '__main__':
    unittest.main()
