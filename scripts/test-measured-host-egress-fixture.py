#!/usr/bin/env python3
"""Reachable outer-guard packet baselines, only in a disposable networkless guest."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

spec = importlib.util.spec_from_file_location('egress', Path(__file__).with_name('measured-host-egress.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
children = []


def run(*args, input=None):
    return subprocess.run(args, input=input, capture_output=True, text=True, check=True, timeout=15).stdout.strip()


def ip(*args):
    return run('ip', *args)


SERVER = '''import socket,sys,threading,time
def serve(address,port,udp):
 family=socket.AF_INET6 if ':' in address else socket.AF_INET
 server=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM); server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6: server.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 server.bind((address,port))
 if not udp: server.listen()
 while True:
  if udp:
   data,peer=server.recvfrom(100); server.sendto(peer[0].encode(),peer)
  else:
   connection,peer=server.accept(); connection.sendall(peer[0].encode()); connection.close()
for address in sys.argv[1:]:
 for port in (25,80,443):
  for udp in (False,True): threading.Thread(target=serve,args=(address,port,udp),daemon=True).start()
while True: time.sleep(1)
'''


def server(namespace, addresses):
    command = ['ip', 'netns', 'exec', namespace] if namespace else []
    children.append(subprocess.Popen(command + ['python3', '-I', '-c', SERVER, *addresses],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))


def connect(address, port=443, allowed=True, peer=None, source='', udp=False, namespace='job'):
    client = '''import socket,sys
try:
 source=(sys.argv[3],0) if sys.argv[3] else None
 if sys.argv[4]=='udp':
  s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,socket.SOCK_DGRAM)
  if source: s.bind(source)
  s.sendto(b'probe',(sys.argv[1],int(sys.argv[2])))
 else: s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=0.4,source_address=source)
 s.settimeout(0.4); print(s.recv(100).decode()); s.close()
except OSError as error: print(str(error),file=sys.stderr); sys.exit(7)
'''
    result = subprocess.run(['ip', 'netns', 'exec', namespace, 'python3', '-I', '-c', client, address, str(port), source, 'udp' if udp else 'tcp'],
                            capture_output=True, text=True, timeout=3)
    assert (result.returncode == 0) == allowed, (address, port, allowed, result.returncode, result.stderr)
    if peer:
        assert result.stdout.strip() == peer


def main():
    assert os.geteuid() == 0 and Path('/.dockerenv').is_file()
    assert json.loads(ip('-j', 'link'))[0]['ifname'] == 'lo'
    assert len(json.loads(ip('-j', 'link'))) == 1 and ip('netns', 'list') == ''
    assert run('nft', 'list', 'tables') == ''
    try:
        for namespace in ('job', 'wan'):
            ip('netns', 'add', namespace)
            ip('-n', namespace, 'link', 'set', 'lo', 'up')
        for local, namespace, address, peer in (
                ('ph0000000000000', 'job', '10.0.1.1/24', '10.0.1.2/24'),
                ('ens3', 'wan', '8.8.4.1/24', '8.8.4.4/24')):
            ip('link', 'add', local, 'type', 'veth', 'peer', 'name', 'peer')
            ip('link', 'set', 'peer', 'netns', namespace)
            ip('address', 'add', address, 'dev', local)
            ip('link', 'set', local, 'up')
            ip('-n', namespace, 'address', 'add', peer, 'dev', 'peer')
            ip('-n', namespace, 'link', 'set', 'peer', 'up')
        ip('-n', 'job', 'route', 'add', 'default', 'via', '10.0.1.1')
        ip('-n', 'wan', 'route', 'add', 'default', 'via', '8.8.4.1')
        ip('-n', 'job', 'address', 'add', '10.0.1.3/24', 'dev', 'peer')
        for local, namespace, address, peer in (
                ('ph0000000000000', 'job', 'fd00:1::1/64', 'fd00:1::2/64'),
                ('ens3', 'wan', '2606:4700:4700::1/64', '2606:4700:4700::1111/64')):
            ip('-6', 'address', 'add', address, 'dev', local, 'nodad')
            ip('-n', namespace, '-6', 'address', 'add', peer, 'dev', 'peer', 'nodad')
            local_mac = json.loads(ip('-j', 'link', 'show', local))[0]['address']
            peer_mac = json.loads(ip('-n', namespace, '-j', 'link', 'show', 'peer'))[0]['address']
            ip('-6', 'neigh', 'replace', peer.split('/')[0], 'lladdr', peer_mac, 'nud', 'permanent', 'dev', local)
            ip('-n', namespace, '-6', 'neigh', 'replace', address.split('/')[0], 'lladdr', local_mac,
               'nud', 'permanent', 'dev', 'peer')
        ip('-n', 'job', '-6', 'route', 'add', 'default', 'via', 'fd00:1::1')
        ip('-n', 'wan', '-6', 'route', 'add', 'default', 'via', '2606:4700:4700::1')
        targets = ('9.9.9.9', '10.8.0.1', '169.254.169.254')
        for address in targets:
            ip('-n', 'wan', 'address', 'add', address + '/32', 'dev', 'lo')
            ip('route', 'add', address + '/32', 'via', '8.8.4.4')
        run('sysctl', '-w', 'net.ipv4.ip_forward=1')
        run('sysctl', '-w', 'net.ipv6.conf.all.forwarding=1')
        server('wan', ['8.8.4.4', '2606:4700:4700::1111', *targets])
        server(None, ['10.0.1.1', '8.8.4.1'])
        time.sleep(0.5)
        for address in ('8.8.4.4', *targets, '10.0.1.1', '8.8.4.1'):
            connect(address)
        connect('8.8.4.4', 25)
        connect('8.8.4.4', source='10.0.1.3')
        connect('2606:4700:4700::1111')
        for address in ('8.8.4.4', *targets, '10.0.1.1', '2606:4700:4700::1111'):
            connect(address, udp=True)
        connect('8.8.4.4', 25, udp=True)
        connect('8.8.4.4', source='10.0.1.3', udp=True)
        run('nft', '-f', '-', input='''table ip fixture_dnat {
 chain prerouting {
  type nat hook prerouting priority -100; policy accept;
  ip daddr 8.8.4.5 dnat to 8.8.4.4
 }
}
''')
        connect('8.8.4.5')
        connect('8.8.4.1', namespace='wan')
        rules = s.render({'version': 1, 'wan': 'ens3', 'hostIPv4': '8.8.4.1',
                          'sensitiveIPv4': ['9.9.9.9/32']})
        run('nft', '--check', '-f', '-', input=rules)
        run('nft', '-f', '-', input=rules)
        connect('8.8.4.4', peer='8.8.4.1')
        connect('8.8.4.4', 80, peer='8.8.4.1')
        for address in (*targets, '10.0.1.1', '8.8.4.1'):
            connect(address, allowed=False)
        connect('8.8.4.4', 25, allowed=False)
        connect('8.8.4.4', source='10.0.1.3', allowed=False)
        connect('2606:4700:4700::1111', allowed=False)
        connect('8.8.4.4', peer='8.8.4.1', udp=True)
        connect('8.8.4.4', 80, peer='8.8.4.1', udp=True)
        for address in (*targets, '10.0.1.1', '2606:4700:4700::1111'):
            connect(address, allowed=False, udp=True)
        connect('8.8.4.4', 25, allowed=False, udp=True)
        connect('8.8.4.4', source='10.0.1.3', allowed=False, udp=True)
        connect('8.8.4.5', allowed=False)
        connect('8.8.4.1', namespace='wan')
        # A later base-chain DROP remains authoritative; accepting in our own
        # table cannot bypass the host firewall's independent deny policy.
        run('nft', '-f', '-', input='table ip host_firewall {\n chain forward {\n type filter hook forward priority 0; policy drop;\n }\n}\n')
        connect('8.8.4.4', allowed=False)
        run('nft', '-f', '-', input='''add rule ip host_firewall forward iifname "ph*" oifname "ens3" ip saddr 10.0.1.2 tcp dport { 80, 443 } accept
add rule ip host_firewall forward iifname "ens3" oifname "ph*" ip daddr 10.0.1.2 ct state established,related accept
''')
        connect('8.8.4.4', peer='8.8.4.1')
        connect('9.9.9.9', allowed=False)
        print(json.dumps({'reachableDenialBaselines': True, 'restrictedSNAT': True,
            'hostInputDenied': True, 'privateMetadataManagementDenied': True,
            'smtpDenied': True, 'independentForwardDropPreserved': True,
            'sourceSpoofDenied': True, 'reachableIPv6BypassDenied': True,
            'tcpAndUdpProbed': True,
            'destinationNATDenied': True, 'unrelatedHostInputPreserved': True,
            'productionChanged': False}))
    except Exception:
        for namespace in ('', 'job', 'wan'):
            prefix = ['ip', 'netns', 'exec', namespace] if namespace else []
            for command in (['ip', '-6', 'route'], ['ip', '-6', 'neigh'],
                            ['sysctl', 'net.ipv6.conf.all.forwarding', 'net.ipv6.conf.all.disable_ipv6']):
                result = subprocess.run(prefix + command, capture_output=True, text=True, timeout=5)
                print(namespace, command, result.stdout[-2048:], flush=True)
        raise
    finally:
        for child in children:
            child.terminate()
        for child in children:
            child.wait(timeout=5)
        for table in ('inet provenance_egress', 'ip provenance_egress_nat', 'ip host_firewall', 'ip fixture_dnat'):
            subprocess.run(['nft', 'delete', 'table', *table.split()], capture_output=True)
        for link in ('ph0000000000000', 'ens3'):
            subprocess.run(['ip', 'link', 'delete', link], capture_output=True)
        for namespace in ('job', 'wan'):
            subprocess.run(['ip', 'netns', 'delete', namespace], capture_output=True)
        assert ip('netns', 'list') == '' and run('nft', 'list', 'tables') == ''
        assert len(json.loads(ip('-j', 'link'))) == 1
        print(json.dumps({'ownedNamespacesLinksAndTablesAbsent': True}))


if __name__ == '__main__':
    main()
