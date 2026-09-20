import importlib.util
from pathlib import Path
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('launch', Path(__file__).with_name('measured-service-launch.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class LaunchTests(unittest.TestCase):
    def test_generation_traversal_requires_one_exact_search_only_identity(self):
        boot = {'generation': '/fixture/generation', 'gid': 981}
        config = {'workload': {'UID': 262144}}
        generation = SimpleNamespace(stat=lambda: SimpleNamespace(st_gid=981, st_mode=0o40710))
        expected = s.generation_acl_bytes(262144)
        with patch.object(s.g, 'protected', return_value=generation), \
                patch.object(s.os, 'getxattr', return_value=expected) as access, \
                patch.object(s.os, 'listxattr', return_value=['system.posix_acl_access']) as names:
            s.verify_generation_traversal(boot, config)
            for value in (b'', expected[:-1], expected.replace(b'\x02\x00\x01\x00', b'\x02\x00\x05\x00')):
                access.return_value = value
                with self.assertRaises(s.g.Refusal):
                    s.verify_generation_traversal(boot, config)
            access.return_value = expected
            names.return_value = ['system.posix_acl_access', 'system.posix_acl_default']
            with self.assertRaises(s.g.Refusal):
                s.verify_generation_traversal(boot, config)
            access.side_effect = OSError('missing ACL')
            with self.assertRaises(OSError):
                s.verify_generation_traversal(boot, config)
        for uid in (True, 994, 262145, 262146, '262144'):
            with self.assertRaises(s.g.Refusal):
                s.generation_acl_bytes(uid)

    def test_uplink_rule_refuses_missing_changed_shadowed_or_dropin_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / s.UPLINK_LINK.name
            with patch.object(s, 'UPLINK_LINK', path), patch.object(s, 'LINK_DIRS', (root,)), \
                    patch.object(s.g, 'protected', return_value=SimpleNamespace(
                        stat=lambda: SimpleNamespace(st_gid=0, st_mode=0o100644, st_nlink=1),
                        read_bytes=path.read_bytes)):
                with self.assertRaises(FileNotFoundError):
                    s.verify_uplink_link()
                path.write_bytes(s.uplink_link_bytes())
                s.verify_uplink_link()
                path.write_bytes(s.uplink_link_bytes().replace(b'none', b'persistent'))
                with self.assertRaises(s.g.Refusal):
                    s.verify_uplink_link()
                path.write_bytes(s.uplink_link_bytes())
                earlier = root / '00-a.link'
                earlier.write_text('[Match]\nOriginalName=*\n')
                with self.assertRaises(s.g.Refusal):
                    s.verify_uplink_link()
                earlier.unlink()
                override = root / (path.name + '.d')
                override.mkdir()
                (override / 'override.conf').write_text('[Link]\nMACAddressPolicy=persistent\n')
                with self.assertRaises(s.g.Refusal):
                    s.verify_uplink_link()

    def test_resource_bounds_are_canonical_and_not_booleans(self):
        for value in (1, '1', 4000, '4000'):
            s.numeric(value, 4000)
        for value in (0, -1, True, False, 1.0, None, '01', '+1', '1 ', '1.0', '4001', 4001):
            with self.subTest(value=value), self.assertRaises(s.g.Refusal):
                s.numeric(value, 4000)

    def test_unit_reserves_controller_and_waits_for_readiness(self):
        units = [{'mountUnit': {'path': '/etc/systemd/system/' + name + '.mount'}}
                 for name in ('image', 'storage', 'secrets')]
        unit = s.unit_bytes(*units).decode()
        for required in ('Requires=user@994.service image.mount storage.mount secrets.mount\n',
                         'After=user@994.service image.mount storage.mount secrets.mount\n',
                         'Type=notify\nNotifyAccess=main\n', 'DelegateSubgroup=controller\n',
                         'MemoryMax=12G\nMemorySwapMax=0\n', 'TasksMax=2048\n',
                         'SendSIGKILL=no\nTimeoutStopSec=infinity\n',
                         'RuntimeDirectoryPreserve=yes\n'):
            self.assertIn(required, unit)
        self.assertNotIn('EnvironmentFile=', unit)
        self.assertIn('ExecStartPre=/usr/bin/python3 -I /opt/provenance-runner/measured-service-launch.py prepare-boot\n', unit)

    def test_boot_preparation_requires_native_prestart_and_ready_mounts(self):
        p={'unit':{'path':'/etc/systemd/system/provenance-measured.service'}}
        boot={'mountUnit':{'path':'/etc/systemd/system/image.mount'}}
        disk={'mountUnit':{'path':'/etc/systemd/system/storage.mount'}}
        calls=[]
        def run(*args):
            calls.append(args)
            if args[2]=='provenance-measured.service':
                return 'start-pre' if args[3]=='--property=SubState' else 'activating'
            return 'active'
        with patch.object(s,'load_inputs',return_value=(p,boot,disk,{})), \
                patch.object(s.b,'run',side_effect=run), patch.object(s.storage,'execute') as storage, \
                patch.object(s,'verify_secrets') as secrets, patch.object(s.b,'execute') as image:
            s.prepare_boot()
        storage.assert_called_once_with(disk,'verify')
        secrets.assert_called_once_with(p)
        image.assert_called_once_with(boot,'ensure')

    def test_boot_preparation_refuses_outside_prestart_before_repair(self):
        p={'unit':{'path':'/etc/systemd/system/provenance-measured.service'}}
        with patch.object(s,'load_inputs',return_value=(p,{}, {},{})), \
                patch.object(s.b,'run',return_value='active'), patch.object(s.b,'execute') as image, \
                self.assertRaises(s.g.Refusal):
            s.prepare_boot()
        image.assert_not_called()

    def test_boot_preparation_refuses_missing_required_mount(self):
        p={'unit':{'path':'/etc/systemd/system/provenance-measured.service'}}
        plan={'mountUnit':{'path':'/etc/systemd/system/image.mount'}}
        with patch.object(s,'load_inputs',return_value=(p,plan,plan,{})), \
                patch.object(s.b,'run',side_effect=['activating','start-pre','inactive']), \
                patch.object(s.b,'execute') as image, self.assertRaises(s.g.Refusal):
            s.prepare_boot()
        image.assert_not_called()

    def test_secret_unit_is_bounded_volatile_and_nonswappable(self):
        unit = s.secret_unit_bytes().decode()
        self.assertIn('Where=/run/provenance-measured/secrets\nType=tmpfs\n', unit)
        self.assertIn('noswap,size=1M,nr_inodes=256,mode=0711', unit)

    def test_wrong_cgroup_placement_refuses_before_writes(self):
        with patch.object(s.Path, 'read_text', return_value='0::/unrelated\n'), \
                patch.object(s, 'control') as control, self.assertRaises(s.g.Refusal):
            s.prepare_cgroups({'cpuMillis': 1000, 'memoryBytes': 128 << 20,
                              'diskBytes': 256 << 20, 'processCount': 64})
        control.assert_not_called()

    def test_wrong_mapping_refuses_before_reading_account_data(self):
        config = {'workerUid': 994, 'workerGid': 981, 'workload': {}, 'router': {}}
        with patch.object(s.pwd, 'getpwnam') as accounts, self.assertRaises(s.g.Refusal):
            s.verify_identities(config, '/must-not-be-imported')
        accounts.assert_not_called()

    def test_exact_job_parent_matches_workload_router_and_runtime_reserve(self):
        self.assertEqual(s.job_limits({'cpuMillis': 1000, 'memoryBytes': '134217728',
                         'diskBytes': '268435456', 'processCount': 64}),
                         {'cpu.max': '200000 100000', 'cpu.max.burst': '0',
                          'memory.max': '268435456', 'memory.swap.max': '0', 'pids.max': '162',
                          'cgroup.max.descendants': '2', 'cgroup.max.depth': '1', 'memory.oom.group': '1'})
        valid = {'cpuMillis': 2000, 'memoryBytes': 4 << 30, 'diskBytes': 8 << 30, 'processCount': 512}
        for change in ({'cpuMillis': 2001}, {'cpuMillis': 9}, {'memoryBytes': (4 << 30) + 1},
                       {'memoryBytes': (16 << 20) - 1}, {'diskBytes': (1 << 20) - 1}, {'processCount': 513}):
            with self.subTest(change=change), self.assertRaises(s.g.Refusal):
                s.job_limits(valid | change)


if __name__ == '__main__':
    unittest.main()
