import importlib.util
import ipaddress
import re
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('egress', Path(__file__).with_name('measured-host-egress.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class EgressTests(unittest.TestCase):
    def plan(self):
        return {'version': 1, 'wan': 'ens3', 'hostIPv4': '135.148.121.196',
                'sensitiveIPv4': ['51.81.202.247/32', '104.250.159.18/32']}

    def test_outer_guard_is_additive_and_has_no_global_flush(self):
        value = s.render(self.plan())
        self.assertNotIn('flush', value)
        self.assertNotIn('sysctl', value)
        self.assertNotIn('ufw', value)
        self.assertIn('ip saddr != 10.0.1.2 counter drop', value)
        self.assertIn('iifname "ph*" counter drop', value)
        self.assertIn('ct status dnat counter drop', value)
        self.assertEqual(value.count('meta nfproto != ipv4 counter drop'), 2)

    def test_inventory_includes_the_host_and_all_special_ipv4_ranges(self):
        value = s.render(self.plan())
        rendered = [ipaddress.ip_network(prefix.strip()) for prefix in re.search(r'elements = \{ ([^}]+)', value)[1].split(', ')]
        for prefix in (*s.SPECIAL, '135.148.121.196/32', '51.81.202.247/32', '104.250.159.18/32'):
            self.assertTrue(any(ipaddress.ip_network(prefix).subnet_of(item) for item in rendered))

    def test_invalid_or_injectable_inputs_refuse(self):
        for change in ({'version': True}, {'extra': 1}, {'wan': 'ens3";flush ruleset'},
                       {'wan': 'lo'}, {'wan': 'ph123'}, {'hostIPv4': '127.0.0.1'},
                       {'hostIPv4': '224.0.0.1'},
                       {'hostIPv4': '::1'}, {'sensitiveIPv4': []},
                       {'sensitiveIPv4': ['1.2.3.4/24']}, {'sensitiveIPv4': ['::/0']},
                       {'sensitiveIPv4': ['1.2.3.4/32'] * 2}):
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                s.render(self.plan() | change)


if __name__ == '__main__':
    unittest.main()
