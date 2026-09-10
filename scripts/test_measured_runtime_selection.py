import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('selection', Path(__file__).with_name('measured-runtime-selection.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
b = s.b


class SelectionTests(unittest.TestCase):
    def boot(self):
        return {'runsc': {'path': '/opt/provenance-runner/runsc'},
                'rootfs': '/opt/g/rootfs', 'loop': '/opt/g/loop',
                'image': {'path': '/opt/g/image.squashfs', 'sha256': 'a' * 64},
                'runtimeEnvironment': '/opt/provenance-runner/runner.env'}

    def test_render_changes_only_owned_assignments_and_keeps_quoted_catalog(self):
        old = (b'# comment\nPROVENANCE_ROOTFS="/old"\n' +
               b'PROVENANCE_PAPER_CATALOGS_JSON="[{\\"version\\":\\"26.2\\"}]"\nOTHER=value\n')
        after = b.render_environment(self.boot(), old)
        actual, other = b.environment(after, b.runtime_values(self.boot()))
        self.assertEqual(b''.join(other), old.replace(b'PROVENANCE_ROOTFS="/old"\n', b''))
        self.assertEqual(actual['PROVENANCE_PAPER_CATALOGS_JSON'], '[{"version":"26.2"}]')
        for key, value in b.runtime_values(self.boot()).items():
            self.assertEqual(actual[key], value)
        self.assertEqual(b.render_environment(self.boot(), after), after)

    def test_ambiguous_environment_refused(self):
        for data in (b'A=x\nA=y\n', b' export A=x\n', b' A=x\n', b'A=x\\\nB=y\n',
                     b'A="x\nPROVENANCE_ROOTFS=/opt/g/rootfs\n"\n', b'A="x" more\n',
                     b'A=\x00\n', b'A=x\r\n', b'A=x', b'A=$(id)\n',
                     b'A=\xff\n', b'A=' + b'x' * (512 * 1024) + b'\n'):
            with self.subTest(data=data[:60]), self.assertRaises((s.g.Refusal, ValueError)):
                b.environment(data, b.runtime_values(self.boot()))

    def test_selected_environment_does_not_pin_unrelated_catalog_revision(self):
        boot = self.boot()
        class File:
            def stat(self):
                from types import SimpleNamespace
                return SimpleNamespace(st_gid=981, st_mode=0o640, st_nlink=1, st_size=1000)
            def read_bytes(self):
                return b.render_environment(boot, b'PROVENANCE_PAPER_CATALOGS_JSON="updated"\n')
        boot['gid'] = 981
        with patch.object(b.g, 'protected', return_value=File()):
            b.selected_environment(boot)

    def test_selected_environment_refuses_missing_or_changed_runtime_value(self):
        boot = self.boot() | {'gid': 981}
        from types import SimpleNamespace
        for data in (b'OTHER=x\n', b.render_environment(boot, b'').replace(b'embedded-executable', b'legacy')):
            f = unittest.mock.Mock()
            f.stat.return_value = SimpleNamespace(st_gid=981, st_mode=0o640, st_nlink=1, st_size=len(data))
            f.read_bytes.return_value = data
            with patch.object(b.g, 'protected', return_value=f), self.assertRaises(s.g.Refusal):
                b.selected_environment(boot)

    def test_drain_refuses_stale_future_nonzero_boolean_and_wrong_plan(self):
        valid = {'version': 1, 'planSha256': 'a' * 64, 'issuedAt': 1000, 'expiresAt': 1200,
                 'platformDrainEvidenceSha256': 'b' * 64, 'activeLeases': 0, 'pendingTerminalReplay': 0}
        for delta in ({}, {'expiresAt': 1050}, {'issuedAt': 1101}, {'expiresAt': 1400},
                      {'activeLeases': 1}, {'activeLeases': False}, {'version': True},
                      {'pendingTerminalReplay': 1}, {'planSha256': 'c' * 64}, {'extra': True}):
            with self.subTest(delta=delta), patch.object(s.g, 'read_json', return_value=valid | delta), \
                    patch.object(s.time, 'time', return_value=1100):
                if not delta:
                    s.drain('/drain', 'd' * 64, 'a' * 64)
                else:
                    with self.assertRaises(s.g.Refusal):
                        s.drain('/drain', 'd' * 64, 'a' * 64)

    def transition_fixture(self, action, fail_after=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oldenv, newenv, oldhook = b'old-env\n', b'new-env\n', b'old-hook\n'
            for name, data in (('before', oldenv), ('after', newenv), ('hook-before', oldhook)):
                (root / name).write_bytes(data)
            p = {'environmentBefore': {'path': str(root / 'before'), 'sha256': s.digest(oldenv)},
                 'environmentAfter': {'path': str(root / 'after'), 'sha256': s.digest(newenv)},
                 'hookBefore': {'path': str(root / 'hook-before'), 'sha256': s.digest(oldhook)},
                 'helper': {'path': '/opt/provenance-runner/measured-rootfs-boot.py'},
                 'bootPlan': {'path': '/opt/boot-plan.json', 'sha256': 'a' * 64}, 'legacyRootfs': {}}
            boot = {'runtimeEnvironment': str(root / 'runner.env')}
            target_env, target_hook = root / 'runner.env', root / 'verify-rootfs'
            target_env.write_bytes(oldenv if action == 'select' else newenv)
            target_hook.write_bytes(oldhook if action == 'select' else s.hook(p))
            writes = []
            def fingerprint(path):
                return {'sha256': s.digest(Path(path).read_bytes())}
            def replace(path, expected, data):
                self.assertEqual(fingerprint(path)['sha256'], expected)
                Path(path).write_bytes(data)
                writes.append(Path(path).name)
                if len(writes) == fail_after:
                    raise OSError('post-rename crash')
            with patch.object(s, 'ROOT', root), patch.object(s, 'state'), \
                    patch.object(s.g, 'legacy'), patch.object(s.g, 'fingerprint', side_effect=fingerprint), \
                    patch.object(s.g, 'replace_file', side_effect=replace), \
                    patch.object(b, 'selected_environment'), patch.object(b, 'execute') as execute:
                check = unittest.mock.Mock()
                if fail_after:
                    with self.assertRaises(OSError):
                        s.transition(p, boot, action, check)
                    self.assertEqual(target_env.read_bytes(), oldenv)
                    self.assertEqual(target_hook.read_bytes(), s.hook(p))
                    # Same reviewed transition resumes, without repeating the
                    # first committed replacement or manufacturing success.
                    fail_after = None
                s.transition(p, boot, action, check)
                self.assertGreaterEqual(check.call_count, 4)
                self.assertEqual(target_env.read_bytes(), newenv if action == 'select' else oldenv)
                self.assertEqual(target_hook.read_bytes(), s.hook(p) if action == 'select' else oldhook)
                self.assertEqual(writes, ['verify-rootfs', 'runner.env'] if action == 'select'
                                 else ['runner.env', 'verify-rootfs'])
                self.assertEqual(execute.call_count, 1 if action == 'select' else 0)

    def test_select_order_and_resume_after_committed_hook(self):
        self.transition_fixture('select')
        self.transition_fixture('select', fail_after=1)

    def test_rollback_order_and_resume_after_committed_environment(self):
        self.transition_fixture('rollback')
        self.transition_fixture('rollback', fail_after=1)

    def test_hook_uses_isolated_python_and_pinned_boot_plan(self):
        p = {'helper': {'path': '/opt/provenance-runner/measured-rootfs-boot.py'},
             'bootPlan': {'path': '/opt/plan.json', 'sha256': 'a' * 64}}
        self.assertEqual(s.hook(p), ('#!/bin/sh\nset -eu\nexec /usr/bin/python3 -I '
                                    '/opt/provenance-runner/measured-rootfs-boot.py ensure '
                                    '--plan /opt/plan.json --plan-sha256 ' + 'a' * 64 + '\n').encode())


if __name__ == '__main__':
    unittest.main()
