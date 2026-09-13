#!/usr/bin/env python3
"""Actual DNS packets in fresh no-network containers; no host mounts or rules."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

CLIENT = r'''
import json,socket,struct,sys
kind,transport,host,source,port=sys.argv[1:]
q=struct.pack('!6H',42,256,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in host.split('.'))+b'\0'+struct.pack('!HH',int(kind),1)
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if transport=='tcp' else socket.SOCK_DGRAM)
s.settimeout(.4);s.bind((source,0));s.connect(('10.0.1.1',int(port)))
try:
 if transport=='tcp':
  s.sendall(struct.pack('!H',len(q))+q)
  def read(n):
   out=b''
   while len(out)<n:
    part=s.recv(n-len(out))
    if not part:raise OSError('closed')
    out+=part
   return out
  data=read(struct.unpack('!H',read(2))[0])
 else:s.sendall(q);data=s.recv(4096)
 result={'responded':True,'rcode':data[3]&15,'answers':struct.unpack('!H',data[6:8])[0],'echo':data==q}
except OSError:result={'responded':False}
finally:s.close()
print(json.dumps(result))
'''
ECHO = r'''
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.0.1.1',54));print('ready',flush=True)
while True:
 data,peer=s.recvfrom(4096);s.sendto(data,peer)
'''


def inside(mode, sentry_enabled=False):
    assert Path('/.dockerenv').is_file() and os.environ.get('PROVENANCE_DISPOSABLE_NETWORK_FIXTURE') == '1'
    def run(*args, namespace=None, **kw):
        return subprocess.check_output((['ip','netns','exec',namespace] if namespace else [])+list(args), text=True, timeout=10, **kw)
    assert [link['ifname'] for link in json.loads(run('ip','-j','link'))] == ['lo']
    owned=[]
    service=echo=sentry=None
    table='pv_10000000000040008000000000000001'
    def probe(kind=1, transport='udp', host='fixture.example.com', source='10.0.1.2', port=53):
        return json.loads(run('python3','-B','-c',CLIENT,str(kind),transport,host,source,str(port),namespace='job'))
    def report():
        line=service.stdout.readline(65537)
        assert line.endswith('\n') and len(line)<=65536, 'bounded fixture report missing'
        return json.loads(line)
    def command(value):
        service.stdin.write(value+'\n');service.stdin.flush()
        return report()
    def accepted_bytes():
        rows=json.loads(run('nft','-j','list','counter','inet',table,'forwarded',namespace='filter'))['nftables']
        return next(row['counter']['bytes'] for row in rows if 'counter' in row)
    evidence={}
    try:
        for name in ('job','filter'):
            if name == 'job' and sentry_enabled:
                fixture=Path('/fixture');fixture.mkdir(mode=0o755)
                for directory in ('bundle','state'):
                    (fixture/directory).mkdir(mode=0o755)
                spec={
                    'ociVersion':'1.0.2', 'root':{'path':'/guestroot','readonly':True},
                    'process':{'terminal':False,'user':{'uid':65532,'gid':65532},
                        'args':['/smoke','dns-lifecycle'],'env':['PATH=/'],'cwd':'/',
                        'noNewPrivileges':True,
                        'capabilities':{key:[] for key in ('bounding','effective','inheritable','permitted','ambient')},
                        'rlimits':[{'type':'RLIMIT_NOFILE','hard':1024,'soft':1024}]},
                    'linux':{'namespaces':[{'type':kind} for kind in ('pid','ipc','uts','mount')]+[{'type':'network','path':'/proc/self/ns/net'}]},
                    'mounts':[]}
                (fixture/'bundle'/'config.json').write_text(json.dumps(spec))
                for directory in ('bundle','state'):
                    os.chown(fixture/directory,65532,65532)
                sentry=subprocess.Popen(['/usr/local/bin/network-sentry-fixture','parent'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                line=sentry.stdout.readline(4097)
                assert line.endswith('\n') and len(line)<=4096, 'mapped namespace report missing'
                pid=json.loads(line)['namespacePID']
                assert type(pid) is int and pid>1
                status=Path(f'/proc/{pid}/status').read_text()
                for kind in ('Uid','Gid'):
                    assert re.search(r'^'+kind+r':\s+65532\s+65532\s+65532\s+65532$',status,re.M)
                assert re.search(r'^Groups:[ \t]*$',status,re.M)
                for kind in ('uid','gid'):
                    assert Path(f'/proc/{pid}/{kind}_map').read_text().split()==['0','65532','1','65534','65533','1']
                run('ip','netns','attach',name,str(pid))
                evidence['callerMappedNetworkNamespace']=True
            else:
                run('ip','netns','add',name)
            owned.append(name)
            run('ip','link','set','lo','up',namespace=name)
        run('ip','link','add','left','type','veth','peer','name','right')
        for ns,old,new,address in (('job','left','eth0','10.0.1.2'),('filter','right','job0','10.0.1.1')):
            run('ip','link','set',old,'netns',ns)
            run('ip','link','set',old,'name',new,namespace=ns)
            run('ip','addr','add',address+'/24','dev',new,namespace=ns)
            run('ip','link','set',new,'up',namespace=ns)
        run('ip','addr','add','10.0.1.99/24','dev','eth0',namespace='job')
        for ns,dev,peer,peerdev,address in (('job','eth0','filter','job0','10.0.1.1'),('filter','job0','job','eth0','10.0.1.2'),('filter','job0','job','eth0','10.0.1.99')):
            mac=json.loads(run('ip','-j','link','show',peerdev,namespace=peer))[0]['address']
            run('ip','neigh','replace',address,'lladdr',mac,'nud','permanent','dev',dev,namespace=ns)
        echo=subprocess.Popen(['ip','netns','exec','filter','python3','-u','-B','-c',ECHO],stdout=subprocess.PIPE,text=True)
        assert echo.stdout.readline().strip()=='ready'
        assert probe(port=54)['echo'] and probe(source='10.0.1.99',port=54)['echo'], 'unfiltered negative destinations unreachable'
        service=subprocess.Popen(['ip','netns','exec','filter','/dns-fixture','-ttl','30s' if sentry_enabled else '8s'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        first=report();assert first['phase']=='ready'
        if sentry_enabled:
            def sentry_report(phase):
                line=sentry.stdout.readline(4097)
                assert line.endswith('\n') and len(line)<=4096, 'bounded live Sentry report missing'
                assert json.loads(line)=={'phase':phase,'nonRootGuest':True}
            sentry.stdin.write('s');sentry.stdin.flush()
            sentry_report('ready')
            evidence['nonRootSentryBoundDNSBothFamiliesBothTransports']=True
        else:
            for kind,transport in ((1,'udp'),(28,'udp'),(1,'tcp'),(28,'tcp')):
                got=probe(kind,transport);assert got.get('rcode')==0 and got.get('answers')==1, got
            assert probe(host='unlisted.example.com').get('rcode')==5
            assert probe(kind=16).get('rcode')==5
            assert not probe(port=54)['responded']
            assert not probe(source='10.0.1.99')['responded']
            evidence['unlistedNamesUnsupportedTypesOtherPortsAndSpoofedSourcesDenied']=True
        before=accepted_bytes();assert before>0
        evidence['bothFamiliesOverUDPAndTCP']=True
        time.sleep(1.1)
        refreshed=command('refresh');assert refreshed['phase']=='refreshed'
        assert accepted_bytes()>=before, 'DNS refresh reset shared byte counter'
        if sentry_enabled:
            sentry.stdin.write('refresh\n');sentry.stdin.flush()
            sentry_report('refreshed')
            evidence['liveSentryRenewalBothFamiliesBothTransports']=True
        else:
            assert probe().get('answers')==1
        evidence['refreshPreservesSharedCounter']=True
        if mode=='expiry':
            old=datetime.datetime.fromisoformat(first['expires'].replace('Z','+00:00')).timestamp()
            new=datetime.datetime.fromisoformat(refreshed['expires'].replace('Z','+00:00')).timestamp()
            assert new>old and 0<new-time.time()<15
            time.sleep(max(0,old-time.time()+.1))
            assert probe().get('answers')==1, 'old input/output expiry survived refresh'
            time.sleep(max(0,new-time.time()+.1))
            assert not probe()['responded'], 'expired kernel snapshot answered DNS'
            evidence['renewedKernelDeadlineAndExpiry']=True
            service.stdin.write('stop\n');service.stdin.flush()
            assert service.wait(timeout=5)==0
        else:
            assert command('withdraw')['phase']=='withdrawn'
            rules=json.loads(run('nft','-j','list','table','inet',table,namespace='filter'))['nftables']
            assert not any('rule' in row for row in rules), 'withdrawal left packet permissions'
            assert accepted_bytes()>=before
            if sentry_enabled:
                sentry.stdin.write('withdraw\n');sentry.stdin.flush()
                sentry_report('withdrawn')
                assert sentry.wait(timeout=5)==0
                evidence['liveSentryWithdrawalBothFamiliesBothTransports']=True
            else:
                assert not probe()['responded']
            service.stdin.write('refresh\n');service.stdin.flush()
            assert service.wait(timeout=5)==1
            assert 'withdrawn fixture cannot refresh' in service.stderr.read(4096)
            evidence['withdrawalClosesAllChainsAndCannotResume']=True
        remaining=json.loads(run('nft','-j','list','tables',namespace='filter'))['nftables']
        assert not any('table' in row for row in remaining), 'fixture table not removed'
        job_link=json.loads(run('ip','-j','link','show','job0',namespace='filter'))[0]
        assert 'UP' not in job_link['flags'], 'table removed before owned job route disconnected'
        evidence['lifecycleControllerDisconnectedOwnedRoute']=True
        evidence['ownedTableRemoved']=True
    finally:
        for process in (sentry,service,echo):
            if process is not None and process.poll() is None:
                process.kill();process.wait(timeout=5)
        for ns in reversed(owned):
            run('ip','netns','delete',ns)
    assert not run('ip','netns','list').strip(), 'owned namespace cleanup incomplete'
    evidence['ownedNamespacesRemoved']=True
    print(json.dumps(evidence,sort_keys=True))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--image');parser.add_argument('--inside',choices=('expiry','withdraw'));parser.add_argument('--go',default='go')
    parser.add_argument('--sentry',action='store_true')
    args=parser.parse_args()
    if args.inside:
        assert not args.sentry or args.inside=='withdraw'
        inside(args.inside,args.sentry);return
    assert args.image and re.fullmatch(r'sha256:[0-9a-f]{64}',args.image), 'pinned local fixture image required'
    root=Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix='provenance-dns-fixture-') as temporary:
        binary=Path(temporary)/'dns-fixture'
        subprocess.run([args.go,'build','-o',str(binary),'./scripts/network-policy/dns-fixture'],cwd=root,env=os.environ|{'CGO_ENABLED':'0'},check=True,timeout=180)
        for mode in (('withdraw',) if args.sentry else ('expiry','withdraw')):
            container='provenance-dns-fixture-'+uuid.uuid4().hex
            try:
                caps=[item for cap in ('NET_RAW','SETUID','SETGID','CHOWN','SYS_PTRACE') for item in ('--cap-add',cap)] if args.sentry else []
                subprocess.run(['docker','create','--name',container,'--network','none','--memory','512m' if args.sentry else '128m','--cpus','1','--pids-limit','256' if args.sentry else '128','--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','SYS_ADMIN','--cap-add','NET_BIND_SERVICE']+caps+['--security-opt','apparmor=unconfined','--security-opt','seccomp=unconfined','-e','PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1','--entrypoint','sleep',args.image,'180'],check=True,stdout=subprocess.DEVNULL,timeout=15)
                subprocess.run(['docker','cp',str(binary),container+':/dns-fixture'],check=True,timeout=15)
                subprocess.run(['docker','cp',str(Path(__file__).resolve()),container+':/dns_acceptance.py'],check=True,timeout=15)
                subprocess.run(['docker','start',container],check=True,stdout=subprocess.DEVNULL,timeout=15)
                subprocess.run(['docker','exec',container,'python3','-B','/dns_acceptance.py','--inside',mode]+(['--sentry'] if args.sentry else []),check=True,timeout=60)
            finally:
                subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)


if __name__=='__main__':main()
