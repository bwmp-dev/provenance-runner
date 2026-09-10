import importlib.util
import os
from pathlib import Path
import stat
import struct
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'boot', Path(__file__).with_name('measured-rootfs-boot.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class BootTests(unittest.TestCase):
    def plan(self):
        return {'uid': 994, 'gid': 981, 'rootfs': '/opt/generation/rootfs',
                'loop': '/opt/generation/loop',
                'image': {'path': '/opt/generation/image.squashfs'},
                'mountUnit': {'path': '/etc/systemd/system/opt-generation-rootfs.mount',
                              'sha256': 'a' * 64},
                'userUnit': {'path': '/etc/systemd/user/provenance-runner.service',
                             'sha256': 'b' * 64}}

    def test_paths_refuse_systemd_expansion_and_noncanonical_inputs(self):
        for value in ('/', 'relative', '/opt//image', '/opt/../image', '/opt/%n',
                      '/opt/a b', '/opt/a\nb', '/opt/a\\b', '/opt/$HOME', None):
            with self.subTest(value=value), self.assertRaises(b.g.Refusal):
                b.safe_path(value)
        self.assertEqual(b.safe_path('/opt/generation/image'), Path('/opt/generation/image'))
        escaped = r'/etc/systemd/system/opt-sha256\x2daaaa-rootfs.mount'
        self.assertEqual(b.safe_path(escaped, mount_unit=True), Path(escaped))
        with self.assertRaises(b.g.Refusal):
            b.safe_path(escaped)
        with self.assertRaises(b.g.Refusal):
            b.safe_path('/etc/systemd/system/%n.mount', mount_unit=True)

    def test_unit_is_mount_only_no_runner_order_or_enable(self):
        unit = b.unit_bytes(self.plan()).decode()
        self.assertIn('Options=loop,ro,nosuid,nodev\n', unit)
        self.assertIn('What=/opt/generation/image.squashfs\n', unit)
        self.assertNotIn('Before=', unit)
        self.assertNotIn('[Install]', unit)
        self.assertNotIn('ExecStart', unit)

    def test_plan_unknown_fields_boolean_version_and_zero_ids_refused(self):
        valid = self.plan() | {'version': 1, 'generation': '/opt/generation',
                               'imageManifest': {}}
        for delta in ({'unknown': True}, {'version': True}, {'uid': 0},
                      {'gid': True}, {'uid': '994'}):
            with self.subTest(delta=delta), patch.object(b.g, 'read_json', return_value=valid | delta):
                with self.assertRaises(b.g.Refusal):
                    b.load_plan('/plan', 'a' * 64)

    def test_loaded_unit_exact_fragment_no_dropins_no_stale_cache(self):
        p = self.plan()
        expected = [p['mountUnit']['path'], '', 'no']
        for values in (expected, ['/foreign', '', 'no'],
                       [expected[0], '/dropin', 'no'], [expected[0], '', 'yes']):
            with self.subTest(values=values), patch.object(b.g, 'fingerprint'):
                ctl = unittest.mock.Mock(side_effect=values)
                if values == expected:
                    b.loaded_unit(p, 'mountUnit', ctl)
                else:
                    with self.assertRaises(b.g.Refusal):
                        b.loaded_unit(p, 'mountUnit', ctl)

    def test_quiet_refuses_runner_and_any_non_init_scope(self):
        for state, scopes, ok in (
                ('inactive', '', True), ('failed', 'init.scope loaded active running System\n', True),
                ('active', '', False), ('activating', '', False),
                ('inactive', 'sandbox.scope loaded active running Job', False),
                ('inactive', 'init.scope loaded activating start Job', False),
                ('inactive', 'init.scope loaded active running System\nx.scope loaded active running Job', False)):
            with self.subTest(state=state, scopes=scopes), patch.object(b, 'loaded_unit'), \
                    patch.object(b, 'userctl', side_effect=[state, scopes]):
                if ok:
                    b.quiet(self.plan())
                else:
                    with self.assertRaises(b.g.Refusal):
                        b.quiet(self.plan())

    def test_ioctl_readonly_and_autoclear_only_expected_flags(self):
        source = SimpleNamespace(st_dev=123, st_ino=456)
        node = SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(7, 8))
        good = [123, 456, 0, 0, 0, 8, 0, 0, 1, b'', b'', b'', 0, 0]
        cases = [(None, None, True), (8, 5, True), (8, 0, False), (8, 4, False),
                 (8, 9, False), (0, 124, False), (1, 457, False), (3, 1, False),
                 (4, 1, False), (5, 9, False), (6, 1, False), (7, 1, False)]
        for index, value, ok in cases:
            info = list(good)
            if index is not None:
                info[index] = value
            def ioctl(fd, request, buf, mutate):
                self.assertEqual(request, 0x4C05)
                buf[:] = struct.pack('=QQQQQIIII64s64s32sQQ', *info)
            with self.subTest(index=index, value=value), \
                    patch.object(Path, 'stat', return_value=source), \
                    patch.object(b.os, 'open', return_value=50), \
                    patch.object(b.os, 'fstat', return_value=node), \
                    patch.object(b.os, 'close') as close, \
                    patch.object(b.fcntl, 'ioctl', side_effect=ioctl):
                if ok:
                    self.assertEqual(b.loop_identity('/dev/loop8', '/image'), node.st_rdev)
                else:
                    with self.assertRaises(b.g.Refusal):
                        b.loop_identity('/dev/loop8', '/image')
                close.assert_called_once_with(50)

    def test_ioctl_failure_closes_fd(self):
        with patch.object(Path, 'stat'), patch.object(b.os, 'open', return_value=50), \
                patch.object(b.os, 'fstat'), patch.object(b.os, 'close') as close, \
                patch.object(b.fcntl, 'ioctl', side_effect=OSError('failure')):
            with self.assertRaises(OSError):
                b.loop_identity('/dev/loop8', '/image')
            close.assert_called_once_with(50)

    def test_mount_refuses_flags_device_and_nested_mounts(self):
        valid = {'fstype': 'squashfs', 'source': '/dev/loop8',
                 'options': 'ro,nosuid,nodev,relatime', 'maj:min': '7:8'}
        for delta, descendants, ok in (
                ({}, '/opt/generation/rootfs', True),
                ({'fstype': 'ext4'}, '/opt/generation/rootfs', False),
                ({'options': 'rw,nosuid,nodev'}, '/opt/generation/rootfs', False),
                ({'options': 'ro,nodev'}, '/opt/generation/rootfs', False),
                ({'maj:min': '7:9'}, '/opt/generation/rootfs', False),
                ({}, '/opt/generation/rootfs\n/opt/generation/rootfs/tmp', False)):
            with self.subTest(delta=delta, descendants=descendants), \
                    patch.object(b.g, 'mount_info', return_value=valid | delta), \
                    patch.object(b, 'loop_identity', return_value=os.makedev(7, 8)), \
                    patch.object(b, 'run', return_value=descendants):
                if ok:
                    self.assertEqual(b.mounted(self.plan()), os.makedev(7, 8))
                else:
                    with self.assertRaises(b.g.Refusal):
                        b.mounted(self.plan())

    def node(self, **changes):
        return SimpleNamespace(**({'st_mode': stat.S_IFBLK | 0o440, 'st_uid': 0,
                                  'st_gid': 981, 'st_nlink': 1, 'st_dev': 1,
                                  'st_ino': 2, 'st_rdev': os.makedev(7, 8)} | changes))

    def test_node_already_correct_does_not_write(self):
        with patch.object(Path, 'lstat', return_value=self.node()), \
                patch.object(b.os, 'mknod') as create:
            b.private_node(self.plan(), os.makedev(7, 8), True)
            create.assert_not_called()

    def test_node_foreign_custody_refused_even_for_repair(self):
        for delta in ({'st_mode': stat.S_IFLNK | 0o777}, {'st_mode': stat.S_IFREG | 0o440},
                      {'st_uid': 994}, {'st_gid': 0}, {'st_nlink': 2},
                      {'st_mode': stat.S_IFBLK | 0o640}, {'st_rdev': os.makedev(8, 1)}):
            with self.subTest(delta=delta), patch.object(Path, 'lstat', return_value=self.node(**delta)), \
                    patch.object(b.os, 'mknod') as create:
                with self.assertRaises(b.g.Refusal):
                    b.private_node(self.plan(), os.makedev(7, 9), True)
                create.assert_not_called()

    def test_verify_never_repairs_missing_or_stale_node(self):
        for result in (None, self.node()):
            with patch.object(Path, 'lstat', side_effect=FileNotFoundError if result is None else None,
                              return_value=result), patch.object(b.os, 'mknod') as create:
                with self.assertRaises(b.g.Refusal):
                    b.private_node(self.plan(), os.makedev(7, 9), False)
                create.assert_not_called()

    def test_repair_only_replaces_private_alias(self):
        with patch.object(Path, 'lstat', return_value=self.node()), \
                patch.object(b.os, 'mknod') as create, patch.object(b.os, 'chown'), \
                patch.object(b.os, 'chmod'), patch.object(b.os, 'replace') as replace, \
                patch.object(b.g, 'sync_directory') as sync, patch.object(b, 'run') as command:
            b.private_node(self.plan(), os.makedev(7, 9), True)
            create.assert_called_once_with(Path('/opt/generation/.loop.pending'),
                                           stat.S_IFBLK | 0o400, os.makedev(7, 9))
            replace.assert_called_once_with(Path('/opt/generation/.loop.pending'),
                                            Path('/opt/generation/loop'))
            sync.assert_called_once_with(Path('/opt/generation'))
            command.assert_not_called()

    def test_preexisting_pending_is_retained(self):
        with patch.object(Path, 'lstat', return_value=self.node()), \
                patch.object(b.os, 'mknod', side_effect=FileExistsError), \
                patch.object(Path, 'unlink') as unlink:
            with self.assertRaises(FileExistsError):
                b.private_node(self.plan(), os.makedev(7, 9), True)
            unlink.assert_not_called()

    def test_metadata_failure_removes_only_owned_temporary(self):
        for substituted in (False, True):
            with patch.object(Path, 'lstat', side_effect=[self.node(), self.node(),
                              self.node(st_ino=3 if substituted else 2)]), \
                    patch.object(b.os, 'mknod'), \
                    patch.object(b.os, 'chown', side_effect=OSError('failure')), \
                    patch.object(Path, 'unlink') as unlink:
                with self.assertRaises(OSError):
                    b.private_node(self.plan(), os.makedev(7, 9), True)
                self.assertEqual(unlink.call_count, 0 if substituted else 1)

    def test_verify_is_readonly_and_does_not_require_stopped_runner(self):
        with patch.object(b, 'loaded_unit'), patch.object(b, 'quiet') as quiet, \
                patch.object(b, 'run') as run, patch.object(b, 'mounted', return_value=123), \
                patch.object(b, 'private_node') as node:
            b.execute(self.plan(), 'verify')
            quiet.assert_not_called()
            run.assert_not_called()
            node.assert_called_once_with(self.plan(), 123, False)

    def test_ensure_active_mount_is_idempotent_and_checks_quiet_twice(self):
        with patch.object(b, 'loaded_unit'), patch.object(b, 'quiet') as quiet, \
                patch.object(b, 'run', return_value='active') as run, \
                patch.object(b, 'mounted', return_value=123), patch.object(b, 'private_node') as node:
            b.execute(self.plan(), 'ensure')
            self.assertEqual(quiet.call_count, 2)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(node.call_args_list, [unittest.mock.call(self.plan(), 123, True),
                                                 unittest.mock.call(self.plan(), 123, False)])

    def test_ensure_refuses_transitional_or_foreign_mount_before_start(self):
        for state in ('activating', 'deactivating', 'inactive'):
            with patch.object(b, 'loaded_unit'), patch.object(b, 'quiet'), \
                    patch.object(b, 'run', return_value=state) as run, \
                    patch.object(b.os.path, 'ismount', return_value=True), \
                    patch.object(b, 'private_node') as node:
                with self.assertRaises(b.g.Refusal):
                    b.execute(self.plan(), 'ensure')
                self.assertEqual(run.call_count, 1)
                node.assert_not_called()

    def test_start_failure_never_repairs_or_detaches(self):
        root = unittest.mock.Mock()
        root.iterdir.return_value = iter(())
        with patch.object(b, 'loaded_unit'), patch.object(b, 'quiet'), \
                patch.object(b.os.path, 'ismount', return_value=False), \
                patch.object(b.g, 'protected', return_value=root), \
                patch.object(b, 'run', side_effect=['inactive', subprocess.TimeoutExpired('systemctl', 90)]) as run, \
                patch.object(b, 'private_node') as node:
            with self.assertRaises(subprocess.TimeoutExpired):
                b.execute(self.plan(), 'ensure')
            self.assertEqual(run.call_count, 2)
            node.assert_not_called()

    def test_nonempty_mountpoint_never_hidden(self):
        root = unittest.mock.Mock()
        root.iterdir.return_value = iter([Path('/foreign')])
        with patch.object(b, 'loaded_unit'), patch.object(b, 'quiet'), \
                patch.object(b.os.path, 'ismount', return_value=False), \
                patch.object(b.g, 'protected', return_value=root), \
                patch.object(b, 'run', return_value='inactive') as run:
            with self.assertRaises(b.g.Refusal):
                b.execute(self.plan(), 'ensure')
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
