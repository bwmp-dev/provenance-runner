#!/usr/bin/env python3
"""Trusted, disposable kernel acceptance. Never configures a host namespace.

Run with --image sha256:... using an image built from the adjacent Dockerfile.
Only the --inside invocation, in a fresh no-network Docker container, can create
namespaces. No host mounts, Docker socket, published ports or production access.
"""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid


SERVER = r'''
import socket, threading, time, queue
ready=queue.Queue()
def tcp(family, port):
    s=socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if family==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
    s.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',port)); s.listen(); ready.put(True)
    def echo(c):
        try:
            while True:
                data=c.recv(65536)
                if not data: break
                c.sendall(data)
        except OSError: pass
        finally: c.close()
    while True:
        c,_=s.accept(); threading.Thread(target=echo,args=(c,),daemon=True).start()
def udp(family, port, address):
    s=socket.socket(family, socket.SOCK_DGRAM)
    if family==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
    s.bind((address,port)); ready.put(True)
    while True:
        data,addr=s.recvfrom(65536); s.sendto(data,addr)
count=0
for family in (socket.AF_INET,socket.AF_INET6):
    for port in (8080,8081,8082):
        threading.Thread(target=tcp,args=(family,port),daemon=True).start(); count+=1
        addresses=('1.1.1.1','1.0.0.1','169.254.169.254','93.184.216.34') if family==socket.AF_INET else ('2606:4700:4700::1111','2606:4700:4700::1001')
        for address in addresses:
            threading.Thread(target=udp,args=(family,port,address),daemon=True).start(); count+=1
for _ in range(count): ready.get(timeout=5)
print('ready',flush=True)
while True: time.sleep(60)
'''

CLIENT = r'''
import json, socket, sys
address,port,protocol=sys.argv[1:]
s=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM)
s.settimeout(.5)
try:
    s.connect((address,int(port))); s.sendall(b'fixture'); ok=s.recv(128)==b'fixture'
except OSError: ok=False
finally: s.close()
print(json.dumps(ok))
'''

CONNECTIONS = r'''
import json, socket
sockets=[]
results=[]
for family,address in ((socket.AF_INET,'1.1.1.1'),(socket.AF_INET6,'2606:4700:4700::1111'),(socket.AF_INET,'1.1.1.1')):
    s=socket.socket(family,socket.SOCK_STREAM); s.settimeout(.5); sockets.append(s)
    try:
        s.connect((address,8080)); s.sendall(b'cap'); results.append(s.recv(32)==b'cap')
    except OSError: results.append(False)
for s in sockets: s.close()
print(json.dumps(results))
'''

RAW = r'''
import json,socket,struct,sys
destination,mac,source=sys.argv[1:]
listener=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); listener.bind((source,44444)); listener.settimeout(.5)
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)); s.bind(('eth0',0))
payload=b'raw-fixture'
udp=struct.pack('!HHHH',44444,8081,8+len(payload),0)+payload
ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),123,0,64,17,0,socket.inet_aton(source),socket.inet_aton(destination))
words=struct.unpack('!10H',ip); checksum=sum(words)
while checksum>>16: checksum=(checksum&65535)+(checksum>>16)
ip=ip[:10]+struct.pack('!H',(~checksum)&65535)+ip[12:]
frame=bytes.fromhex(mac.replace(':',''))+s.getsockname()[4]+struct.pack('!H',0x0800)+ip+udp
s.send(frame)
try: ok=listener.recv(128)==payload
except OSError: ok=False
print(json.dumps(ok))
'''

FLOOD = r'''
import socket
sockets=[]
for family,address in ((socket.AF_INET,'1.1.1.1'),(socket.AF_INET6,'2606:4700:4700::1111')):
    s=socket.socket(family,socket.SOCK_DGRAM)
    if family==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
    s.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',44000))
    s.connect((address,8081)); sockets.append(s)
for _ in range(1000):
    for s in sockets: s.send(b'x'*1000)
for s in sockets: s.close()
'''

EXPIRY = r'''
import datetime,json,socket,sys,time
deadline=datetime.datetime.fromisoformat(sys.argv[1]).timestamp()
s=socket.socket(); s.settimeout(.5); s.connect(('1.1.1.1',8080)); s.sendall(b'before')
assert s.recv(128)==b'before', 'binding already expired before fixture started'
remaining=deadline-time.time()
assert 0<remaining<35, remaining
time.sleep(remaining+.05)
try:
    s.sendall(b'after'); allowed=s.recv(128)==b'after'
except OSError: allowed=False
s.close()
print(json.dumps(not allowed))
'''


REFRESH_FLOWS = r'''
import json,socket,sys
sockets=[]
for address in ('1.1.1.1','2606:4700:4700::1111'):
 s=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_STREAM)
 s.settimeout(.5);s.connect((address,8080));s.sendall(b'before');assert s.recv(6)==b'before';sockets.append(s)
print('ready',flush=True)
assert sys.stdin.readline().strip()=='refresh'
for s in sockets:
 s.sendall(b'after');assert s.recv(5)==b'after'
third=socket.socket();third.settimeout(.5);blocked=False
try:
 third.connect(('1.1.1.1',8080));third.sendall(b'third');blocked=third.recv(5)!=b'third'
except OSError:blocked=True
assert blocked
third.close();print('refreshed-cap-preserved',flush=True)
assert sys.stdin.readline().strip()=='withdraw'
for s in sockets:
 denied=False
 try:s.sendall(b'denied');denied=s.recv(6)!=b'denied'
 except OSError:denied=True
 assert denied;s.close()
print('withdrawn-established-denied',flush=True)
'''


def inside(sentry_enabled=False):
    if not Path('/.dockerenv').exists() or os.environ.get('PROVENANCE_DISPOSABLE_NETWORK_FIXTURE') != '1':
        raise RuntimeError('disposable container marker required')
    rules = json.load(sys.stdin)
    owned = []
    server = None
    sentry = None
    flows = None

    def run(*args, namespace=None, input=None, timeout=10):
        command = (['ip', 'netns', 'exec', namespace] if namespace else []) + list(args)
        result = subprocess.run(command, input=input, text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f'{command[:5]} failed: {result.stderr[:4096]}')
        return result.stdout

    def ip(namespace, *args):
        return run('ip', *args, namespace=namespace)

    def reset():
        run('nft', '-f', '-', namespace='filter', input=rules['remove'])
        run('conntrack', '-F', namespace='filter')
        run('nft', '-f', '-', namespace='filter', input=rules['install'])

    def probe(address, port, protocol):
        return json.loads(run('python3', '-B', '-c', CLIENT, address, str(port), protocol, namespace='job'))

    evidence = {}
    try:
        assert [link['ifname'] for link in json.loads(run('ip', '-j', 'link'))] == ['lo'], 'container must have network=none'
        # Docker masks /proc/sys by default. This fresh proc mount affects only
        # the disposable container's private mount/PID namespaces. All sysctl writes
        # below still execute inside the newly created filter network namespace.
        run('mount', '-t', 'proc', 'proc', '/proc')
        for ns in ('job', 'filter', 'wan'):
            if ns == 'job' and sentry_enabled:
                fixture = Path('/fixture')
                fixture.mkdir(mode=0o755)
                for name in ('bundle', 'state'):
                    (fixture/name).mkdir(mode=0o755)
                spec = {
                    'ociVersion': '1.0.2',
                    'root': {'path': '/guestroot', 'readonly': True},
                    'process': {
                        'terminal': False, 'user': {'uid': 65532, 'gid': 65532},
                        'args': ['/smoke', 'probe-lifecycle'], 'env': ['PATH=/'], 'cwd': '/',
                        'noNewPrivileges': True,
                        'capabilities': {key: [] for key in ('bounding', 'effective', 'inheritable', 'permitted', 'ambient')},
                        'rlimits': [{'type': 'RLIMIT_NOFILE', 'hard': 1024, 'soft': 1024}],
                    },
                    'linux': {'namespaces': [{'type': name} for name in ('pid', 'ipc', 'uts', 'mount')] + [{'type': 'network', 'path': '/proc/self/ns/net'}]},
                    'mounts': [],
                }
                (fixture/'bundle'/'config.json').write_text(json.dumps(spec))
                for name in ('bundle', 'state'):
                    os.chown(fixture/name, 65532, 65532)
                sentry = subprocess.Popen(['/usr/local/bin/network-sentry-fixture', 'parent'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                first = sentry.stdout.readline()
                if not first:
                    raise RuntimeError('mapped namespace failed: ' + sentry.stderr.read(4096))
                pid = json.loads(first)['namespacePID']
                status = Path(f'/proc/{pid}/status').read_text()
                assert re.search(r'^Uid:\s+65532\s+65532\s+65532\s+65532$', status, re.M), status
                assert re.search(r'^Gid:\s+65532\s+65532\s+65532\s+65532$', status, re.M), status
                assert re.search(r'^Groups:[ \t]*$', status, re.M), status
                assert Path(f'/proc/{pid}/uid_map').read_text().split() == ['0', '65532', '1', '65534', '65533', '1']
                assert Path(f'/proc/{pid}/gid_map').read_text().split() == ['0', '65532', '1', '65534', '65533', '1']
                run('ip', 'netns', 'attach', ns, str(pid))
                evidence['callerMappedNetworkNamespace'] = True
            else:
                run('ip', 'netns', 'add', ns)
            owned.append(ns)
            ip(ns, 'link', 'set', 'lo', 'up')
        for left, leftdev, left4, left6, right, rightdev, right4, right6 in (
            ('job', 'eth0', '10.0.1.2', 'fd00:1::2', 'filter', 'job0', '10.0.1.1', 'fd00:1::1'),
            ('filter', 'wan0', '10.0.2.1', 'fd00:2::1', 'wan', 'eth0', '10.0.2.2', 'fd00:2::2'),
        ):
            run('ip', 'link', 'add', 'left', 'type', 'veth', 'peer', 'name', 'right')
            run('ip', 'link', 'set', 'left', 'netns', left)
            run('ip', 'link', 'set', 'right', 'netns', right)
            for ns, old, dev, v4, v6 in ((left, 'left', leftdev, left4, left6), (right, 'right', rightdev, right4, right6)):
                ip(ns, 'link', 'set', old, 'name', dev)
                ip(ns, 'addr', 'add', v4+'/24', 'dev', dev)
                ip(ns, '-6', 'addr', 'add', v6+'/64', 'dev', dev, 'nodad')
                ip(ns, 'link', 'set', dev, 'up')
            for ns, dev, peer, peerdev, v4, v6 in ((left, leftdev, right, rightdev, right4, right6), (right, rightdev, left, leftdev, left4, left6)):
                mac = json.loads(ip(peer, '-j', 'link', 'show', peerdev))[0]['address']
                for address in (v4, v6):
                    ip(ns, 'neigh', 'replace', address, 'lladdr', mac, 'nud', 'permanent', 'dev', dev)
        for ns, v4, v6 in (('job', '10.0.1.1', 'fd00:1::1'), ('filter', '10.0.2.2', 'fd00:2::2'), ('wan', '10.0.2.1', 'fd00:2::1')):
            ip(ns, 'route', 'add', 'default', 'via', v4)
            ip(ns, '-6', 'route', 'add', 'default', 'via', v6)
        for address in ('1.1.1.1/32', '1.0.0.1/32', '169.254.169.254/32', '93.184.216.34/32', '2606:4700:4700::1111/128', '2606:4700:4700::1001/128'):
            ip('wan', 'addr', 'add', address, 'dev', 'lo', *(['nodad'] if ':' in address else []))
        run('sysctl', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1', namespace='filter')
        # Additional fixture-only alias makes spoofed-source replies observable;
        # it is deliberately not the compiler's authorized workload address.
        ip('job', 'addr', 'add', '10.0.1.99/24', 'dev', 'eth0')
        server = subprocess.Popen(['ip', 'netns', 'exec', 'wan', 'python3', '-u', '-B', '-c', SERVER], stdout=subprocess.PIPE, text=True)
        if server.stdout.readline().strip() != 'ready':
            raise RuntimeError('fixture server did not start')
        # Prove the synthetic endpoints are reachable before installing policy;
        # a missing service/route must never masquerade as a successful denial.
        for address in ('1.1.1.1', '1.0.0.1', '169.254.169.254', '93.184.216.34', '2606:4700:4700::1111', '2606:4700:4700::1001'):
            for port, protocol in ((8080, 'tcp'), (8081, 'udp'), (8080, 'udp'), (8081, 'tcp'), (8082, 'tcp')):
                assert probe(address, port, protocol), ('unfiltered endpoint unreachable', address, port, protocol)
        mac = json.loads(ip('filter', '-j', 'link', 'show', 'job0'))[0]['address']
        assert json.loads(run('python3', '-B', '-c', RAW, '1.1.1.1', mac, '10.0.1.99', namespace='job')), 'unfiltered spoofed-source fixture unreachable'
        # Exercise the short absolute deadline before the many deliberately
        # timed-out denial probes. Those probes can consume the entire binding
        # lifetime on a busy CI host. Do not extend or rewrite its real expiry.
        run('conntrack', '-F', namespace='filter')
        run('nft', '-f', '-', namespace='filter', input=rules['expiry']['install'])
        assert json.loads(run('python3', '-B', '-c', EXPIRY, rules['expiry']['expires'], namespace='job', timeout=40)), 'established flow outlived binding'
        assert not probe('1.1.1.1', 8080, 'tcp'), 'new flow accepted after expiry'
        assert not probe('2606:4700:4700::1111', 8081, 'udp'), 'IPv6 flow accepted after expiry'
        evidence['absoluteExpiryClosesEstablishedAndNewFlows'] = True
        run('nft', '-f', '-', namespace='filter', input=rules['remove'])
        run('conntrack', '-F', namespace='filter')
        run('nft', '-c', '-f', '-', namespace='filter', input=rules['install'])
        run('nft', '-f', '-', namespace='filter', input=rules['install'])
        evidence['syntaxAndUnfilteredReachability'] = True
        for address in ('1.1.1.1', '2606:4700:4700::1111'):
            for port, protocol, expected in ((8080, 'tcp', True), (8081, 'udp', True), (8080, 'udp', False), (8081, 'tcp', False), (8082, 'tcp', False)):
                reset()
                assert probe(address, port, protocol) == expected, (address, port, protocol, run('nft', 'list', 'ruleset', namespace='filter'))
        evidence['ipv4Ipv6WholeTuples'] = True
        for address in ('1.0.0.1', '169.254.169.254', '93.184.216.34', '2606:4700:4700::1001'):
            reset()
            assert not probe(address, 8080, 'tcp'), ('unbound destination allowed', address)
        evidence['unboundPrivateMetadataManagementDenied'] = True
        reset()
        result = json.loads(run('python3', '-B', '-c', CONNECTIONS, namespace='job'))
        assert result == [True, True, False], result
        evidence['sharedDualStackConcurrentCap'] = True
        mac = json.loads(ip('filter', '-j', 'link', 'show', 'job0'))[0]['address']
        for address, expected in (('1.1.1.1', True), ('1.0.0.1', False), ('169.254.169.254', False)):
            reset()
            assert json.loads(run('python3', '-B', '-c', RAW, address, mac, '10.0.1.2', namespace='job')) == expected, ('raw L2', address)
        evidence['rawL2RoutedEnforcement'] = True
        reset()
        assert not json.loads(run('python3', '-B', '-c', RAW, '1.1.1.1', mac, '10.0.1.99', namespace='job')), 'spoofed raw source forwarded'
        evidence['rawSourceSpoofingDenied'] = True
        reset()
        start = time.monotonic()
        run('python3', '-B', '-c', FLOOD, namespace='job')
        time.sleep(.1)
        elapsed = time.monotonic() - start
        table = 'pv_10000000000040008000000000000001'
        def counter(name):
            objects = json.loads(run('nft', '-j', 'list', 'counter', 'inet', table, name, namespace='filter'))['nftables']
            return next(item['counter'] for item in objects if 'counter' in item)
        forwarded, denied = counter('forwarded'), counter('bandwidth_denied')
        assert denied['packets'] > 0 and forwarded['bytes'] > 0, (forwarded, denied)
        assert forwarded['bytes'] <= 65536*(1+elapsed), (forwarded, elapsed)
        evidence['aggregateDualStackBidirectionalByteCap'] = {'forwardedBytes': forwarded['bytes'], 'deniedPackets': denied['packets'], 'elapsedSeconds': elapsed}
        # ONE nft transaction replaces only grant sets/rules. The shared byte
        # bucket, counters and connection-count object must not be recreated.
        run('nft', '-f', '-', namespace='filter', input=rules['refresh'])
        assert counter('forwarded')['bytes'] >= forwarded['bytes'], 'refresh reset accepted-byte accounting'
        assert counter('bandwidth_denied')['packets'] >= denied['packets'], 'refresh reset denial accounting'
        run('python3', '-B', '-c', FLOOD, namespace='job')
        time.sleep(.1)
        total = counter('forwarded')['bytes']
        duration = time.monotonic()-start
        assert total > forwarded['bytes'], 'renewed flood must reach rate limiter on the same two flows'
        assert total <= 65536*(1+duration), ('refresh replenished bandwidth bucket', total, duration)
        evidence['atomicRefreshPreservesBudgetAndCounters'] = {'forwardedBytes': total, 'elapsedSeconds': duration}
        reset()  # No live workload yet; start a separate persistent-flow fixture.
        flows = subprocess.Popen(['ip', 'netns', 'exec', 'job', 'python3', '-u', '-B', '-c', REFRESH_FLOWS], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert flows.stdout.readline().strip() == 'ready', 'persistent dual-stack flows not established'
        run('nft', '-f', '-', namespace='filter', input=rules['refresh'])
        try:
            run('nft', '-f', '-', namespace='filter', input=rules['refresh']+'add rule inet '+table+' nonexistent accept\n')
        except RuntimeError:
            pass
        else:
            raise AssertionError('invalid atomic transaction unexpectedly accepted')
        flows.stdin.write('refresh\n'); flows.stdin.flush()
        assert flows.stdout.readline().strip() == 'refreshed-cap-preserved', 'renewal broke flows or reset connection cap'
        evidence['atomicRefreshAndFailedBatchPreserveLiveFlowsAndCap'] = True
        run('nft', '-f', '-', namespace='filter', input=rules['withdraw'])
        output, diagnostics = flows.communicate('withdraw\n', timeout=5)
        assert flows.returncode == 0 and output.strip() == 'withdrawn-established-denied', diagnostics[:4096]
        for address in ('1.1.1.1', '2606:4700:4700::1111'):
            assert not probe(address, 8080, 'tcp') and not probe(address, 8081, 'udp'), 'withdrawal allowed new traffic'
        evidence['withdrawalClosesExistingAndNewDualStackTraffic'] = True
        if sentry_enabled:
            # The existing packet suite completes before starting the guest, so
            # resetting its synthetic table here cannot create a live-guest gap.
            run('nft', '-f', '-', namespace='filter', input=rules['remove'])
            run('conntrack', '-F', namespace='filter')
            run('nft', '-f', '-', namespace='filter', input=rules['sentry']['install'])
            def guest_report():
                line=sentry.stdout.readline(4097)
                assert line.endswith('\n') and len(line)<=4096, 'bounded live Sentry packet report missing'
                return json.loads(line)
            sentry.stdin.write('s');sentry.stdin.flush()
            result = guest_report()
            assert len(result) == 10 and all(value is True for value in result.values()), result
            evidence['userNamespacedSentryPacketPolicy'] = result
            assert guest_report()=={'phase':'flows-ready'}
            before=counter('forwarded')['bytes']
            run('nft', '-f', '-', namespace='filter', input=rules['sentry']['refresh'])
            assert counter('forwarded')['bytes']>=before, 'live Sentry refresh reset counters'
            sentry.stdin.write('refresh\n');sentry.stdin.flush()
            assert guest_report()=={'phase':'flows-refreshed'}
            run('nft', '-f', '-', namespace='filter', input=rules['sentry']['withdraw'])
            sentry.stdin.write('withdraw\n');sentry.stdin.flush()
            assert guest_report()=={'phase':'flows-withdrawn'}
            assert sentry.wait(timeout=5)==0
            evidence['liveSentryRefreshPreservesEstablishedDualStackTCPUDP']=True
            evidence['liveSentryWithdrawalDeniesEstablishedAndNewDualStackTCPUDP']=True
        run('nft', '-f', '-', namespace='filter', input=rules['remove'])
        assert not json.loads(run('nft', '-j', 'list', 'tables', namespace='filter'))['nftables'][1:], 'owned tables remain'
        evidence['ownedTablesRemoved'] = True
    finally:
        if flows is not None and flows.poll() is None:
            flows.terminate()
            flows.wait(timeout=5)
        if sentry is not None and sentry.poll() is None:
            sentry.terminate()
            sentry.wait(timeout=5)
        if server is not None:
            server.terminate()
            server.wait(timeout=5)
        for ns in reversed(owned):
            run('ip', 'netns', 'delete', ns)
    assert run('ip', 'netns', 'list').strip() == '', 'owned namespaces remain'
    evidence['ownedNamespacesRemoved'] = True
    print(json.dumps(evidence, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--image')
    parser.add_argument('--go', default='go')
    parser.add_argument('--sentry', action='store_true')
    args = parser.parse_args()
    if args.inside:
        inside(args.sentry)
        return
    if not args.image or not re.fullmatch(r'sha256:[0-9a-f]{64}', args.image):
        parser.error('--image must be an exact locally built sha256 image ID')
    root = Path(__file__).resolve().parents[2]
    def compile_rules(ttl, connections=2, refresh=False):
        return json.loads(subprocess.run([args.go, 'run', './scripts/network-policy/fixture-rules', '-ttl', ttl, '-connections', str(connections), *(['-refresh'] if refresh else [])], cwd=root, capture_output=True, text=True, check=True, timeout=60).stdout)
    rules = compile_rules('5m', refresh=True)
    if args.sentry:
        rules['sentry'] = compile_rules('5m', 16, refresh=True)
    rules['expiry'] = compile_rules('30s')
    container = 'provenance-network-fixture-' + uuid.uuid4().hex
    try:
        command = [
            'docker', 'run', '--name', container, '--rm', '-i',
            '--network', 'none', '--memory', '512m' if args.sentry else '256m', '--cpus', '1', '--pids-limit', '256' if args.sentry else '128',
            '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'SYS_ADMIN', '--cap-add', 'NET_RAW',
            *(['--cap-add', 'SETUID', '--cap-add', 'SETGID', '--cap-add', 'CHOWN', '--cap-add', 'SYS_PTRACE'] if args.sentry else []),
            '--security-opt', 'apparmor=unconfined', '--security-opt', 'seccomp=unconfined',
            '-e', 'PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1', '--entrypoint', 'python3',
            args.image, '-B', '-c', Path(__file__).read_text(), '--inside', *(['--sentry'] if args.sentry else []),
        ]
        result = subprocess.run(command, input=json.dumps(rules), text=True, timeout=120)
        if result.returncode:
            raise RuntimeError(f'disposable packet acceptance failed: exit {result.returncode}')
    finally:
        # Exact newly generated target only, including on timeout/interrupt.
        subprocess.run(['docker', 'rm', '-f', container], capture_output=True, timeout=15)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda signum, _frame: sys.exit(128 + signum))
    main()
