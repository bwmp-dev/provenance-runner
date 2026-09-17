import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('launch', Path(__file__).with_name('measured-service-launch.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class LaunchTests(unittest.TestCase):
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
        for required in ('Requires=image.mount storage.mount secrets.mount\n',
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
