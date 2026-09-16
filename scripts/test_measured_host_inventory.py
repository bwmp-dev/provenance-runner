import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('inventory', Path(__file__).with_name('measured-host-inventory.py'))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class HostInventoryTests(unittest.TestCase):
    def test_subordinate_ranges_are_half_open_and_not_account_presence(self):
        ranges = inventory.ranges('ubuntu:100000:65536\nprovenance:165536:65536\n', True)
        self.assertEqual(inventory.conflicts({99999, 100000, 200000, 231071, 231072, 262144}, ranges), [100000, 200000, 231071])
        self.assertEqual(inventory.account_ids('root:x:0:0:root:/root:/bin/sh\n', False), {0})
        self.assertEqual(inventory.account_ids('user:x:1000:262144::/:/bin/false\n', False), {1000, 262144})

    def test_namespace_maps_bound_host_ranges(self):
        self.assertEqual(inventory.ranges('0 262144 1\n65532 262145 1\n', False), [(262144, 262145), (262145, 262146)])
        for raw in ('0 1 0', '0 -1 1', '0 4294967294 2', '0 1', 'x 1 1'):
            with self.subTest(raw=raw), self.assertRaises(AssertionError):
                inventory.ranges(raw, False)

    def test_process_effective_saved_and_supplementary_ids(self):
        raw = 'Name:\tprivate-name-not-returned\nUid:\t1 2 3 4\nGid:\t5 6 7 8\nGroups:\t9 10\n'
        self.assertEqual(inventory.process_ids(raw), ({1, 2, 3, 4}, {5, 6, 7, 8, 9, 10}))
        for bad in ('Uid:\t1 2 3 4\n', raw+'Uid:\t1 2 3 4\n', raw.replace('1 2 3 4', '1 2 -3 4')):
            with self.assertRaises(AssertionError):
                inventory.process_ids(bad)

    def test_malformed_account_or_subordinate_inventory_fails_closed(self):
        for raw in ('root:x:0', 'root:x:-1:0:root:/root:/bin/sh'):
            with self.assertRaises(AssertionError):
                inventory.account_ids(raw, False)
        for raw in (':1:2', 'user:1:0', 'user:4294967294:2', 'user:1:2:3'):
            with self.assertRaises(AssertionError):
                inventory.ranges(raw, True)


if __name__ == '__main__':
    unittest.main()
