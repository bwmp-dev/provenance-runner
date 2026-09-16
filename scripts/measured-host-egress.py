#!/usr/bin/env python3
"""Render a narrow outer IPv4 boundary; never apply rules or change sysctls."""
import argparse
import ipaddress
import json
import re
import sys

SPECIAL = ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
           '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
           '192.31.196.0/24', '192.52.193.0/24', '192.88.99.0/24', '192.168.0.0/16',
           '192.175.48.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
           '224.0.0.0/4', '240.0.0.0/4')


def render(config):
    if not isinstance(config, dict) or set(config) != {'version', 'wan', 'hostIPv4', 'sensitiveIPv4'}:
        raise ValueError('closed host network plan required')
    if type(config['version']) is not int or config['version'] != 1:
        raise ValueError('unsupported host network plan')
    wan = config['wan']
    if not isinstance(wan, str) or not re.fullmatch('[a-zA-Z][a-zA-Z0-9_-]{0,14}', wan) or wan == 'lo' or wan.startswith('ph'):
        raise ValueError('fixed physical egress interface required')
    host = ipaddress.IPv4Address(config['hostIPv4'])
    if not host.is_global or any(host in ipaddress.IPv4Network(prefix) for prefix in SPECIAL) or str(host) != config['hostIPv4']:
        raise ValueError('canonical public host address required')
    sensitive = config['sensitiveIPv4']
    if not isinstance(sensitive, list) or not 1 <= len(sensitive) <= 128 or len(set(sensitive)) != len(sensitive):
        raise ValueError('bounded explicit sensitive inventory required')
    prefixes = [ipaddress.IPv4Network(value, strict=True) for value in sensitive]
    if any(str(prefix) != value for prefix, value in zip(prefixes, sensitive)):
        raise ValueError('canonical sensitive prefixes required')
    prefixes += [ipaddress.IPv4Network(value) for value in SPECIAL] + [ipaddress.IPv4Network(str(host) + '/32')]
    denied = ', '.join(str(prefix) for prefix in ipaddress.collapse_addresses(prefixes))
    # This outer guard supplements, never replaces, per-job authenticated
    # policy and DNS grants. UFW's own forward DROP still applies afterwards.
    return f'''table inet provenance_egress {{
 set denied4 {{ type ipv4_addr; flags interval; elements = {{ {denied} }} }}
 chain input {{
  type filter hook input priority -10; policy accept;
  iifname "ph*" counter drop
 }}
 chain forward {{
  type filter hook forward priority -10; policy accept;
  iifname "ph*" jump from_job
  oifname "ph*" jump to_job
 }}
 chain from_job {{
  meta nfproto != ipv4 counter drop
  ip saddr != 10.0.1.2 counter drop
  ip daddr @denied4 counter drop
  ct status dnat counter drop
  oifname != "{wan}" counter drop
  ct state invalid counter drop
  tcp dport {{ 80, 443 }} ct state {{ new, established }} counter accept
  udp dport {{ 80, 443 }} ct state {{ new, established }} counter accept
  counter drop
 }}
 chain to_job {{
  meta nfproto != ipv4 counter drop
  iifname != "{wan}" counter drop
  ip daddr != 10.0.1.2 counter drop
  ip saddr @denied4 counter drop
  ct state {{ established, related }} counter accept
  counter drop
 }}
}}
table ip provenance_egress_nat {{
 chain postrouting {{
  type nat hook postrouting priority 100; policy accept;
  iifname "ph*" oifname "{wan}" ip saddr 10.0.1.2 counter masquerade
 }}
}}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=argparse.FileType('r'))
    args = parser.parse_args()
    raw = args.plan.read(65537)
    if len(raw) > 65536:
        raise ValueError('plan too large')
    print(render(json.loads(raw)), end='')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError):
        print('host egress plan refused', file=sys.stderr)
        sys.exit(1)
