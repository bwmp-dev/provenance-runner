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


class HostOS(unittest.TestCase):
    def test_supported_lts_releases(self):
        for version in ('24.04', '26.04'):
            with self.subTest(version=version), patch.object(i.platform, 'freedesktop_os_release',
                    return_value={'ID': 'ubuntu', 'VERSION_ID': version}):
                i.supported_host_os()

    def test_other_releases_and_derivatives_are_refused(self):
        for release in ({}, {'ID': 'ubuntu'}, {'VERSION_ID': '26.04'},
                *({'ID': 'ubuntu', 'VERSION_ID': v} for v in ('22.04', '24.10', '26.10', '26.04.1', '28.04')),
                {'ID': 'debian', 'VERSION_ID': '26.04'},
                {'ID': 'linuxmint', 'ID_LIKE': 'ubuntu', 'VERSION_ID': '24.04'}):
            with self.subTest(release=release), patch.object(i.platform, 'freedesktop_os_release', return_value=release):
                with self.assertRaisesRegex(ValueError, 'Ubuntu 24.04 or 26.04'):
                    i.supported_host_os()

    def test_unreadable_os_metadata_fails_closed(self):
        with patch.object(i.platform, 'freedesktop_os_release', side_effect=OSError('unavailable')):
            with self.assertRaises(OSError):
                i.supported_host_os()


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




class SignedInstallationURLs(unittest.TestCase):
    def test_bounded_sigv4_assets_only(self):
        url = ('https://assets.example.com/pin?X-Amz-Algorithm=AWS4-HMAC-SHA256'
               '&X-Amz-Credential=key%2Fscope&X-Amz-Date=20260908T000000Z'
               '&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=abc')
        i.https(url)
        for bad in (url+'&token=secret', url+'&X-Amz-Expires=1', url.replace('86400','86401')):
            with self.assertRaises(ValueError): i.https(bad)
        with self.assertRaises(ValueError): i.https(url, origin=True)


class BootstrapPermissions(unittest.TestCase):
    def test_explicit_service_modes_survive_private_bootstrap_umask(self):
        import os
        import stat
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            previous = os.umask(0o077)
            try:
                for name, mode in [('root', 0o755), ('state', 0o711)]:
                    i.directory(root/name, mode)
                    self.assertEqual(stat.S_IMODE((root/name).stat().st_mode), mode)
                for name, mode in [('runner.env', 0o640), ('runsc-rootless', 0o755), ('user.service', 0o644), ('credential', 0o600)]:
                    i.write(root/name, 'test', mode)
                    self.assertEqual(stat.S_IMODE((root/name).stat().st_mode), mode)
            finally:
                os.umask(previous)

    def test_asset_bound_matches_default_runner_cache_entry_limit(self):
        value = settings()
        value['preparedRuntime'].update(sizeBytes=512*1024**2, maximumExpandedBytes=1024**3)
        i.validate(value)
        value['preparedRuntime']['sizeBytes'] += 1
        with self.assertRaises(ValueError):
            i.validate(value)


class InstallationFlow(unittest.TestCase):
    def test_prepare_installs_exact_credentials_modes_and_verified_cache(self):
        import os
        import hashlib
        from contextlib import ExitStack
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            bundle = base/'bundle'
            bundle.mkdir()
            for name in ['runner', 'runsc', 'prepare-gvisor-rootfs.sh', 'SOURCE_COMMIT']:
                (bundle/name).write_text('fixture-'+name)
            value = settings()
            token = 'phc_v1_' + __import__('base64').urlsafe_b64encode(bytes(32)).decode().rstrip('=')
            (base/'credential').write_text(token+'\n')
            value['platformCredentialFile'] = str(base/'credential')
            payloads = {'probe': b'verified probe bytes', 'preparedRuntime': b'verified runtime bytes'}
            for name, payload in payloads.items():
                value[name]['sha256'] = hashlib.sha256(payload).hexdigest()
                value[name]['sizeBytes'] = len(payload)
            settings_path = base/'settings.json'
            settings_path.write_text(json.dumps(value))
            def run(*args, **kwargs):
                if args[0] == 'curl':
                    target = Path(args[args.index('--output')+1])
                    target.write_bytes(payloads[target.name])
                if args[0].endswith('prepare-gvisor-rootfs.sh'):
                    return i.TREE
                return ''
            real_temp = tempfile.TemporaryDirectory
            with ExitStack() as stack:
                for key, val in {'ROOT':base/'opt', 'STATE':base/'state', 'SYSTEM_UNIT':base/'system.service', 'USER_UNIT':base/'user.service', 'PROFILE':base/'apparmor'}.items():
                    stack.enter_context(patch.object(i,key,val))
                stack.enter_context(patch.object(i,'protected'))
                stack.enter_context(patch.object(i,'validate',side_effect=lambda v:v))
                stack.enter_context(patch.object(i,'verify_bundle'))
                stack.enter_context(patch.object(i,'host_preflight'))
                stack.enter_context(patch.object(i,'run',side_effect=run))
                stack.enter_context(patch.object(i,'as_user'))
                stack.enter_context(patch.object(i.os,'chown'))
                stack.enter_context(patch.object(i.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())))
                stack.enter_context(patch.object(i.tempfile,'TemporaryDirectory',side_effect=lambda **kwargs:real_temp(dir=base)))
                previous = os.umask(0o077)
                try:
                    i.install(bundle,settings_path,True)
                finally:
                    os.umask(previous)
                self.assertEqual(i.ROOT.stat().st_mode & 0o777,0o755)
                self.assertEqual(i.STATE.stat().st_mode & 0o777,0o711)
                self.assertEqual((i.ROOT/'runner.env').stat().st_mode & 0o777,0o640)
                self.assertEqual((i.STATE/'config/credential').read_bytes(),token.encode())
                self.assertEqual(i.USER_UNIT.stat().st_mode & 0o777,0o644)
                for name,payload in payloads.items():
                    sha=value[name]['sha256']
                    cached=i.STATE/'cache/content/sha256'/sha[:2]/sha[2:]
                    self.assertEqual(cached.read_bytes(),payload)
                    self.assertEqual(cached.stat().st_mode & 0o777,0o444)
                self.assertTrue((i.ROOT/'installed.json').exists())
                self.assertFalse((i.ROOT/'INSTALLING').exists())


if __name__ == '__main__':
    unittest.main()
