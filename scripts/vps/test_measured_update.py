"""Measured binary/config/launch-pin transaction and every mixed crash state."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('updater_measured_test', Path(__file__).with_name('updater.py'))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


class MeasuredUpdate(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.work = self.root / 'update-state'
        self.work.mkdir(mode=0o700)
        self.planpath, self.configpath = self.root / 'launch.json', self.root / 'config.json'
        for name, value in (('ROOT', self.root), ('WORK', self.work), ('MEASURED_PLAN', self.planpath),
                            ('MEASURED_CONFIG', self.configpath), ('MEASURED_CGROUP', self.root / 'absent-cgroup')):
            context = patch.object(u, name, value)
            context.start()
            self.addCleanup(context.stop)
        # Temp files belong to this unprivileged test account. Production
        # custody is separate and is never bypassed by the actual updater.
        context = patch.object(u, 'protected')
        context.start()
        self.addCleanup(context.stop)
        context = patch.object(u, 'measured_private', side_effect=lambda path: u.read(path))
        context.start()
        self.addCleanup(context.stop)
        def commands(*args):
            if '--property=Requires' in args:
                return b'provenance-measured.service provenance-host-network.service\n'
            if '--property=ActiveState' in args:
                return b'inactive\n'
            return b''
        context = patch.object(u, 'run', side_effect=commands)
        self.run = context.start()
        self.addCleanup(context.stop)
        self.old, self.new = b'old measured binary', b'new signed measured binary'
        self.oldhash, self.newhash = [hashlib.sha256(value).hexdigest() for value in (self.old, self.new)]
        (self.root / 'runner').write_bytes(self.old)
        (self.root / 'installed.json').write_text(json.dumps({'runnerSha256': self.oldhash}))
        self.config = {'version': 1, 'runnerSha256': self.oldhash, 'secretRoot': '/run/private-secrets',
                       'maximumPolicy': {'network': {'mode': 'ALLOWLIST'}}}
        self.configraw = json.dumps(self.config, indent=2).encode()
        self.configpath.write_bytes(self.configraw)
        self.plan = {'version': 1, 'runner': {'path': str(self.root / 'runner'), 'sha256': self.oldhash},
                     'config': {'path': str(self.configpath), 'sha256': hashlib.sha256(self.configraw).hexdigest()}}
        self.planraw = json.dumps(self.plan, indent=2).encode()
        self.planpath.write_bytes(self.planraw)
        self.operation = '10000000-0000-0000-0000-000000000123'
        self.record = u.measured_snapshot(self.operation, self.oldhash, self.newhash)
        self.op = {'id': self.operation, 'phase': 'staged', 'oldSha256': self.oldhash,
                   'release': {'sha256': self.newhash}, 'measured': self.record}
        for digest, value in ((self.oldhash, self.old), (self.newhash, self.new)):
            (self.work / (digest + '.elf')).write_bytes(value)
        self.updater = u.Updater({}, None)

    def snapshot(self, state, name):
        return (self.work / self.record['directory'] / (state + '-' + name + '.json')).read_bytes()

    def test_changes_only_runner_and_config_digest_bindings(self):
        after = json.loads(self.snapshot('after', 'config'))
        self.assertEqual(after, self.config | {'runnerSha256': self.newhash})
        plan = json.loads(self.snapshot('after', 'plan'))
        self.assertEqual(plan['runner'], self.plan['runner'] | {'sha256': self.newhash})
        self.assertEqual(plan['config']['sha256'], hashlib.sha256(self.snapshot('after', 'config')).hexdigest())
        self.assertEqual(self.configpath.read_bytes(), self.configraw)
        self.assertEqual(self.planpath.read_bytes(), self.planraw)
        self.assertEqual(u.measured_snapshot(self.operation, self.oldhash, self.newhash), self.record)

    def test_all_eight_crash_states_restore_exact_before_bytes(self):
        for binary, config, plan in itertools.product(('before', 'after'), repeat=3):
            with self.subTest(binary=binary, config=config, plan=plan):
                (self.root / 'runner').write_bytes(self.old if binary == 'before' else self.new)
                self.configpath.write_bytes(self.snapshot(config, 'config'))
                self.planpath.write_bytes(self.snapshot(plan, 'plan'))
                self.updater.switch(self.work / (self.oldhash + '.elf'), self.oldhash, self.op)
                self.assertEqual((self.root / 'runner').read_bytes(), self.old)
                self.assertEqual(self.configpath.read_bytes(), self.configraw)
                self.assertEqual(self.planpath.read_bytes(), self.planraw)

    def test_each_atomic_write_crash_is_recoverable(self):
        original = u.atomic
        for failure in range(1, 5):
            with self.subTest(failure=failure):
                count = 0
                def crash(*args, **kwargs):
                    nonlocal count
                    original(*args, **kwargs)
                    count += 1
                    if count == failure:
                        raise OSError('simulated post-fsync crash')
                with patch.object(u, 'atomic', side_effect=crash), self.assertRaises(OSError):
                    self.updater.switch(self.work / (self.newhash + '.elf'), self.newhash, self.op)
                self.updater.switch(self.work / (self.oldhash + '.elf'), self.oldhash, self.op)
                self.assertEqual((self.root / 'runner').read_bytes(), self.old)
                self.assertEqual(self.configpath.read_bytes(), self.configraw)
                self.assertEqual(self.planpath.read_bytes(), self.planraw)

    def test_unknown_operator_edit_refuses_before_replacing_binary(self):
        self.configpath.write_bytes(self.configraw + b' ')
        with patch.object(u, 'atomic') as write, self.assertRaises(ValueError):
            self.updater.switch(self.work / (self.newhash + '.elf'), self.newhash, self.op)
        write.assert_not_called()
        self.assertEqual((self.root / 'runner').read_bytes(), self.old)

    def test_corrupt_retained_projection_refuses(self):
        target = self.work / self.record['directory'] / 'after-plan.json'
        target.write_bytes(target.read_bytes() + b' ')
        with patch.object(u, 'atomic') as write, self.assertRaises(ValueError):
            self.updater.switch(self.work / (self.newhash + '.elf'), self.newhash, self.op)
        write.assert_not_called()

    def test_missing_transaction_or_live_cgroup_refuses(self):
        for operation in (None, self.op):
            if operation:
                u.MEASURED_CGROUP.mkdir()
            with patch.object(u, 'atomic') as write, self.assertRaises(ValueError):
                self.updater.switch(self.work / (self.newhash + '.elf'), self.newhash, operation)
            write.assert_not_called()

    def test_worker_stop_waits_for_root_owner_and_checks_group_retirement(self):
        self.run.reset_mock()
        u.service('stop')
        self.assertEqual(self.run.call_args_list[0].args, ('systemctl', 'stop', u.UNIT))
        self.assertEqual(self.run.call_args_list[1].args, ('systemctl', 'stop', u.MEASURED_UNIT))
        u.MEASURED_CGROUP.mkdir()
        with self.assertRaises(ValueError):
            u.service('stop')

    def test_missing_worker_dependency_refuses_before_snapshot(self):
        with patch.object(u, 'run', return_value=b'user@994.service\n'), self.assertRaises(ValueError):
            u.measured_snapshot('10000000-0000-0000-0000-000000000124', self.oldhash, self.newhash)
        self.assertFalse((self.work / 'measured-10000000-0000-0000-0000-000000000124').exists())


if __name__ == '__main__':
    unittest.main()
