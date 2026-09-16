import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location('storage', Path(__file__).with_name('measured-storage.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class StorageTests(unittest.TestCase):
    def superblock(self):
        data = bytearray(1024)
        struct.pack_into('<I', data, 0, 4096)
        struct.pack_into('<I', data, 4, 16384)
        struct.pack_into('<I', data, 24, 2)
        struct.pack_into('<H', data, 56, 0xef53)
        struct.pack_into('<I', data, 92, 0x4)
        struct.pack_into('<I', data, 96, 0x40)
        data[104:120] = uuid.UUID('01234567-89ab-cdef-0123-456789abcdef').bytes
        return data

    def test_geometry_and_64_bit_blocks(self):
        data = self.superblock()
        self.assertEqual(s.geometry(data), {'sizeBytes': 64 << 20, 'blockBytes': 4096,
                         'inodes': 4096, 'uuid': '01234567-89ab-cdef-0123-456789abcdef'})
        struct.pack_into('<I', data, 96, 0xc0)
        struct.pack_into('<I', data, 336, 1)
        self.assertEqual(s.geometry(data)['sizeBytes'], ((1 << 32) + 16384) * 4096)

    def test_bad_geometry_refused(self):
        for length, magic, log in ((1000, 0xef53, 2), (1024, 0, 2), (1024, 0xef53, 3)):
            data = self.superblock()
            struct.pack_into('<H', data, 56, magic)
            struct.pack_into('<I', data, 24, log)
            with self.assertRaises(s.g.Refusal):
                s.geometry(data[:length])
        for offset in (92, 96):
            data = self.superblock()
            struct.pack_into('<I', data, offset, 0)
            with self.assertRaises(s.g.Refusal):
                s.geometry(data)

    def test_unit_cannot_format_resize_or_execute_service(self):
        data = s.unit_bytes({'backing': {'path': '/protected/disk.ext4'}, 'mountpoint': '/protected/data'})
        self.assertEqual(data, b'[Unit]\nDescription=Provenance bounded persistent staging\n\n'
                         b'[Mount]\nWhat=/protected/disk.ext4\nWhere=/protected/data\nType=ext4\n'
                         b'Options=loop,rw,nosuid,nodev,noexec\nTimeoutSec=60\n')

    def test_verify_does_not_start_mount(self):
        plan = {'mountUnit': {'path': '/etc/systemd/system/fixture.mount'}}
        with patch.object(s, 'backing'), patch.object(s.b, 'loaded_unit'), \
                patch.object(s, 'mounted') as mounted, patch.object(s.b, 'run') as run:
            s.execute(plan, 'verify')
            run.assert_not_called()
            mounted.assert_called_once_with(plan)

    def test_ensure_refuses_foreign_or_transitioning_mount(self):
        plan = {'mountUnit': {'path': '/etc/systemd/system/fixture.mount'}, 'mountpoint': '/data'}
        for state, foreign in (('activating', False), ('inactive', True)):
            with patch.object(s, 'backing'), patch.object(s.b, 'loaded_unit'), \
                    patch.object(s.b, 'run', return_value=state) as run, \
                    patch.object(s.os.path, 'ismount', return_value=foreign), \
                    self.assertRaises(s.g.Refusal):
                s.execute(plan, 'ensure')
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
