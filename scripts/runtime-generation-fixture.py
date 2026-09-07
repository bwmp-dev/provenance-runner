"""Disposable-container integration, not an ordinary unit-test module."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import shutil
import atexit
import fcntl
import time
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('generation','/repo/scripts/runtime-generation.py')
g=importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
owned=[]
observed=[]


def resources(p):
    dest=Path(p['generation'])
    loops=g.run('losetup','--noheadings','--output','NAME','--associated',str(dest/'image')).splitlines() if (dest/'image').exists() else []
    mounted=subprocess.run(['mountpoint','--quiet',str(dest/'rootfs')],check=False).returncode==0
    return {'generation':str(dest),'associatedLoops':loops,'mounted':mounted}


def checked_absent(p):
    row=resources(p)
    check(not row['associatedLoops'] and not row['mounted'])
    return row


def cleanup_owned():
    for p in reversed(owned):
        dest=Path(p['generation'])
        if dest.exists():
            try:g.detach(p,'a'*64,(dest/'pending.json').exists())
            except Exception:
                print('FIXTURE CLEANUP INCOMPLETE: retain container for diagnosis',file=sys.stderr)
                os._exit(1)


def case_plan(base,image,name):
    area=base/name
    area.mkdir(mode=0o711)
    parent=area/'generations'
    parent.mkdir(mode=0o711)
    def pin(path):return {'path':str(path),'sha256':g.fingerprint(path)['sha256']}
    digest=g.fingerprint(image)['sha256']
    dest=parent/('sha256-'+digest)
    config=area/'current.env'
    old=b'# protected unrelated fixture bytes\nOTHER=fixture-secret-must-not-appear\nPROVENANCE_ROOTFS=/old\n'
    g.write_new(config,old)
    nextconfig=area/'next.env'
    values={'PROVENANCE_RUNSC_PATH':str(dest/'runsc'),'PROVENANCE_ROOTFS':str(dest/'rootfs'),
            'PROVENANCE_ROOTFS_IDENTITY':'sha256:'+digest,'PROVENANCE_MEASURED_RUNTIME_MODE':'embedded-executable',
            'PROVENANCE_GVISOR_CGROUP_DRIVER':'systemd-user','PROVENANCE_MEASURED_ROOTFS_IMAGE':str(dest/'image'),
            'PROVENANCE_MEASURED_LOOP_DEVICE':str(dest/'loop')}
    g.write_new(nextconfig,old.rsplit(b'PROVENANCE_ROOTFS=',1)[0]+''.join(k+'='+v+'\n' for k,v in values.items()).encode())
    unit=area/(name+'.service')
    unitbytes=('[Service]\nUser=1001\nGroup=1001\nEnvironmentFile='+str(config)+'\nExecStart='+str(base/'runner')+' connect\n').encode()
    g.write_new(unit,unitbytes)
    nextunit=area/'next.service'
    g.write_new(nextunit,unitbytes.replace(str(base/'runner').encode(),str(dest/'runner').encode()))
    return {'version':1,'generation':str(dest),'uid':1001,'gid':1001,
            'runner':pin(base/'runner'),'currentRunner':pin(base/'runner'),'runsc':pin(base/'runsc'),
            'image':pin(image),'imageManifest':pin(base/'image-manifest.json'),
            'currentConfig':pin(config),'newConfig':pin(nextconfig),'unit':pin(unit),'newUnit':pin(nextunit)}


def failure_matrix(base,image):
    # Small real ELF objects keep repeated filesystem fault cases bounded.
    # Real runner/runsc execution remains the separate mandatory guest proof.
    for name in ('small-runner','small-runsc'):g.write_new(base/name,Path('/bin/true').read_bytes(),0o550)
    stages=['mkdir-generation','chmod-generation','chown-generation','sync-parent','write-pending.json',
            'write-previous.env','write-previous.service']
    stages += ['fsync-'+name for name in ('pending.json','previous.env','previous.service','allocated.json','state.json')]
    for name in ('runner','runsc','image'):
        stages += ['open-'+name,'partial-copy-'+name,'fsync-'+name,'chown-'+name,'chmod-'+name]
    stages += ['mkdir-rootfs','chmod-rootfs','chown-rootfs','allocate-before','allocate-after',
               'write-allocated.json','mapping','mknod','chmod-loop','chown-loop','mount-before','mount-after',
               'write-state.json','verify','unlink-pending-before','unlink-pending-after','sync-journal','sync-complete']
    rows=[]
    for index,stage in enumerate(stages):
        p=case_plan(base,image,'fault-'+str(index))
        for name in ('runner','runsc'):
            p[name]={'path':str(base/('small-'+name)),'sha256':g.fingerprint(base/('small-'+name))['sha256']}
        dest=Path(p['generation']);parent=dest.parent
        fired=False
        target=None;method=None;match=None;after=False;partial=False
        if stage.startswith('write-'):
            target,method=g,'write_new';match=lambda a:Path(a[0])==dest/stage.removeprefix('write-')
        elif stage.startswith(('mkdir-','chmod-')):
            method=stage.split('-')[0];target=g.Path
            name=stage.split('-',1)[1];path=dest if name=='generation' else dest/name
            match=lambda a:Path(a[0])==path
        elif stage.startswith('chown-'):
            target,method=g.os,'chown';name=stage.removeprefix('chown-');path=dest if name=='generation' else dest/name
            match=lambda a:Path(a[0])==path
        elif stage.startswith('open-'):
            target,method=g.os,'open';path=dest/stage.removeprefix('open-')
            match=lambda a:Path(a[0])==path and a[1]&os.O_CREAT
        elif stage.startswith('partial-copy-'):
            target,method=g.shutil,'copyfileobj';source=p[stage.removeprefix('partial-copy-')]['path'];partial=True
            match=lambda a:a[0].name==source
        elif stage.startswith('fsync-'):
            target,method=g.os,'fsync';path=dest/stage.removeprefix('fsync-')
            match=lambda a:os.readlink('/proc/self/fd/'+str(a[0]))==str(path)
        elif stage.startswith('sync-'):
            target,method=g,'sync_directory';path=parent if stage=='sync-parent' else dest
            match=lambda a:Path(a[0])==path and (stage=='sync-parent' or ((dest/'pending.json').exists() if stage=='sync-journal' else not (dest/'pending.json').exists()))
        elif stage.startswith('allocate-'):
            target,method=g,'run';match=lambda a:a[:4]==('losetup','--find','--show','--read-only');after=stage.endswith('after')
        elif stage.startswith('mount-'):
            target,method=g,'run';match=lambda a:a[0]=='mount';after=stage.endswith('after')
        elif stage=='mapping':target,method,match=g,'verify_mapping',lambda a:True
        elif stage=='mknod':target,method,match=g.os,'mknod',lambda a:True
        elif stage=='verify':target,method,match=g,'verify',lambda a:True
        elif stage.startswith('unlink-pending-'):
            target,method=g.Path,'unlink';match=lambda a:Path(a[0])==dest/'pending.json';after=stage.endswith('after')
        original=getattr(target,method)
        def fail(*args,**kwargs):
            nonlocal fired
            if not fired and match(args):
                fired=True
                if after:original(*args,**kwargs)
                if partial:args[1].write(b'partial-fixture-write')
                raise g.Refusal('injected '+stage)
            return original(*args,**kwargs)
        owned.append(p)
        with patch.object(target,method,fail):refuse(lambda:g.install(p,'a'*64))
        check(fired)
        refuse(lambda:g.install(p,'a'*64)) if (dest/'pending.json').exists() else None
        before=resources(p)
        recovery='no-directory-created'
        if dest.exists():
            try:
                g.detach(p,'a'*64,(dest/'pending.json').exists())
                recovery='owned-detach'
            except (g.Refusal,OSError):
                # A missing journal or partial copied file is intentionally
                # not adopted. This is safe only before kernel allocation.
                check(not before['associatedLoops'] and not before['mounted'])
                recovery='retained-incomplete-files-no-kernel-resources'
        row=checked_absent(p);observed.append(row)
        owned.remove(p)
        rows.append({'stage':stage,'injectionReached':fired,'recovery':recovery,
                     'allocatedBeforeRecovery':bool(before['associatedLoops']),'postCleanup':row})
    print(json.dumps({'failureMatrix':rows,'syntheticElfs':'container /bin/true; never executed'}))


def cli_tests(base,image):
    # This fake exists ONLY in this new container. It models manager state,
    # never invokes systemd and explicitly rejects service lifecycle commands.
    shim=Path('/usr/sbin/systemctl')
    check(not shim.exists() and not shim.is_symlink())
    statepath=base/'fake-systemd.json'
    shimbytes=b'''#!/usr/bin/python3
import hashlib,json,sys
from pathlib import Path
p=Path('/opt/generation-fixture/fake-systemd.json')
s=json.loads(p.read_text()); a=sys.argv[1:]; s['calls'].append(a)
if a==['daemon-reload']:
 s['loaded']=hashlib.sha256(Path(s['unit']).read_bytes()).hexdigest(); result=''
elif len(a)==4 and a[0]=='show' and a[3]=='--value':
 key=a[2].removeprefix('--property=')
 if key=='FragmentPath': s['drains']+=1
 values={'FragmentPath':s['unit'],'DropInPaths':'','User':'1001','Group':'1001','ActiveState':'inactive',
 'NeedDaemonReload':'no' if s['loaded']==hashlib.sha256(Path(s['unit']).read_bytes()).hexdigest() else 'yes'}
 if s.get('secondDrainActive') and s['drains']>=2: values['ActiveState']='active'
 if a[1] not in (Path(s['unit']).name,'user@1001.service') or key not in values: sys.exit(2)
 result=values[key]
else: sys.exit(2)
p.write_text(json.dumps(s)); print(result)
'''
    g.write_new(shim,shimbytes,0o755)
    p=case_plan(base,image,'cli')
    area=Path(p['unit']['path']).parent
    source=area/'legacy-source'
    root=area/'legacy-root'
    source.mkdir(mode=0o711);root.mkdir(mode=0o711)
    g.write_new(source/'retained',b'legacy retained\n')
    def mount_legacy():
        g.run('mount','--bind',str(source),str(root))
        g.run('mount','-o','remount,bind,ro',str(root))
    mount_legacy()
    tree=hashlib.sha256(subprocess.check_output(['tar','--sort=name','--format=gnu','--mtime=@0',
        '--owner=0','--group=0','--numeric-owner','-cf','-','-C',str(root),'.'])).hexdigest()
    p['legacyRootfs']={'path':str(root),'treeSha256':tree}
    planfile=area/'plan.json';drainfile=area/'drain.json'
    results=[]
    def invoke(action,plan=None,okay=True,drain_delta=None,wrong_plan_hash=False,raw_plan=None,wrong_drain_hash=False):
        value=p if plan is None else plan
        planfile.write_bytes(g.encoded(value) if raw_plan is None else raw_plan);planfile.chmod(0o600)
        digest=hashlib.sha256(planfile.read_bytes()).hexdigest()
        now=int(time.time())
        drain={'version':1,'planSha256':digest,'issuedAt':now,'expiresAt':now+300,
               'platformDrainEvidenceSha256':'b'*64,'activeLeases':0,'pendingTerminalReplay':0}
        drain.update(drain_delta or {})
        drainfile.write_bytes(g.encoded(drain));drainfile.chmod(0o600)
        result=subprocess.run([sys.executable,'/repo/scripts/runtime-generation.py',action,'--plan',str(planfile),
            '--plan-sha256','0'*64 if wrong_plan_hash else digest,'--drain',str(drainfile),
            '--drain-sha256','0'*64 if wrong_drain_hash else hashlib.sha256(drainfile.read_bytes()).hexdigest()],capture_output=True,text=True,timeout=60)
        check((result.returncode==0)==okay)
        check('fixture-secret-must-not-appear' not in result.stdout+result.stderr)
        if okay:check(json.loads(result.stdout)['serviceStarted'] is False)
        else:check(result.stderr=='refusing: runtime generation prerequisites or identities invalid\n')
        return digest
    state={'unit':p['unit']['path'],'loaded':p['unit']['sha256'],'calls':[],'drains':0}
    statepath.write_bytes(g.encoded(state));statepath.chmod(0o600)
    try:
        # A genuinely valid protected plan must reach every later negative.
        planfile.write_bytes(g.encoded(p));planfile.chmod(0o600)
        check(g.load_plan(planfile,g.fingerprint(planfile)['sha256'])==p)
        g.legacy(p)
        for label,change in [('unknown-field',{'unknown':1}),('version',{'version':2}),('boolean-uid',{'uid':True}),
                             ('destination',{'generation':str(area/'not-content-addressed')}),
                             ('legacy-hash',{'legacyRootfs':p['legacyRootfs']|{'treeSha256':'0'*64}})]:
            invoke('install',p|change,False);check(not Path(p['generation']).exists());results.append(label)
        invoke('install',okay=False,wrong_plan_hash=True);results.append('plan-hash')
        invoke('install',okay=False,raw_plan=g.encoded(p).rstrip()[:-1]+b',"version":1}')
        results.append('duplicate-plan-member')
        invoke('install',p|{'runsc':p['runner']},False);results.append('overlapping-inputs')
        for name in ('runner','currentRunner','runsc','image','imageManifest','currentConfig','newConfig','unit','newUnit'):
            invoke('install',p|{name:p[name]|{'sha256':'0'*64}},False)
            results.append('pin-'+name)
        manifest=json.loads(Path(p['imageManifest']['path']).read_text())
        for key,value in [('sha256','0'*64),('sizeBytes',1),('runnerUid',1002),('runnerGid',1002),('reproducibleBuilds',1),('format','wrong')]:
            changed=area/('manifest-'+key+'.json');g.write_new(changed,g.encoded(manifest|{key:value}))
            invoke('install',p|{'imageManifest':{'path':str(changed),'sha256':g.fingerprint(changed)['sha256']}},False)
            results.append('manifest-'+key)
        link=area/'runner-link';link.symlink_to(p['runner']['path'])
        invoke('install',p|{'runner':p['runner']|{'path':str(link)}},False);results.append('actual-protected-symlink')
        area.chmod(0o777)
        try:invoke('install',okay=False)
        finally:area.chmod(0o711)
        results.append('writable-ancestry')
        for delta in ({'activeLeases':1},{'pendingTerminalReplay':1},{'expiresAt':0},{'planSha256':'0'*64}):
            invoke('install',okay=False,drain_delta=delta)
        invoke('install',okay=False,wrong_drain_hash=True)
        results.append('actual-drain-record-refusals')
        process=subprocess.Popen(['setpriv','--reuid','1001','--regid','1001','--clear-groups','sleep','30'])
        try:
            for _ in range(50):
                if Path('/proc',str(process.pid)).stat().st_uid==1001:break
                time.sleep(0.01)
            check(Path('/proc',str(process.pid)).stat().st_uid==1001)
            invoke('install',okay=False)
        finally:process.terminate();process.wait(timeout=5)
        results.append('actual-runtime-uid-process-refusal')
        fd=os.open(Path(p['generation']).parent,os.O_RDONLY|os.O_DIRECTORY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            invoke('install',okay=False)
        finally:os.close(fd)
        results.append('generation-lock-contention')
        state.update(drains=0,secondDrainActive=True);statepath.write_bytes(g.encoded(state))
        invoke('install',okay=False);check(not Path(p['generation']).exists())
        results.append('second-drain-before-mutation')
        state['secondDrainActive']=False;state['drains']=0;statepath.write_bytes(g.encoded(state))
        g.run('mount','-o','remount,bind,rw',str(root))
        invoke('install',okay=False)
        g.run('mount','-o','remount,bind,ro',str(root));results.append('writable-legacy-mount')
        (source/'retained').write_bytes(b'changed\n');invoke('install',okay=False)
        (source/'retained').write_bytes(b'legacy retained\n');results.append('changed-legacy-tree')
        g.run('umount',str(root));invoke('install',okay=False);mount_legacy();results.append('unmounted-legacy')
        identity=invoke('install');invoke('verify');invoke('install');invoke('select');invoke('select')
        invoke('rollback');invoke('rollback')
        check(Path(p['currentConfig']['path']).read_bytes().endswith(b'PROVENANCE_ROOTFS=/old\n'))
        check(g.fingerprint(p['unit']['path'])['sha256']==p['unit']['sha256'])
        observed.append(checked_absent(p));results.append('full-cli-install-verify-select-rollback-idempotence')
        calls=json.loads(statepath.read_text())['calls']
        check(sum(call==['daemon-reload'] for call in calls)==2)
        check(all(call[0] in ('show','daemon-reload') for call in calls))
        legacy_pin=p['legacyRootfs']
        p=case_plan(base,image,'cli-recovery')|{'legacyRootfs':legacy_pin}
        state.update(unit=p['unit']['path'],loaded=p['unit']['sha256'],drains=0,calls=[])
        statepath.write_bytes(g.encoded(state))
        identity=invoke('install')
        g.write_new(Path(p['generation'])/'pending.json',g.encoded({'version':1,'planSha256':identity}))
        invoke('verify',okay=False);invoke('recover')
        observed.append(checked_absent(p));results.append('full-cli-journalled-recovery')
        print(json.dumps({'cliTests':results,'manager':'container-local-stateful-fake','reloadCalls':2,'planSha256':identity}))
    finally:
        if (Path(p['generation'])/'state.json').exists():
            g.detach(p,hashlib.sha256(g.encoded(p)).hexdigest())
        if subprocess.run(['mountpoint','--quiet',str(root)],check=False).returncode==0:g.run('umount',str(root))
        shim.unlink()


atexit.register(cleanup_owned)


def check(condition):
    if not condition: raise AssertionError('generation fixture assertion')


def refuse(f):
    try: f()
    except (g.Refusal,subprocess.SubprocessError,OSError): return
    raise AssertionError('expected refusal')


def main(image):
    check(os.geteuid()==0 and Path('/.dockerenv').is_file())
    base=Path('/opt/generation-fixture')
    parents=base/'generations'
    parents.mkdir(mode=0o711)
    h=g.fingerprint(image)['sha256']
    dest=parents/('sha256-'+h)
    config=base/'current.env'
    old=b'# retained exactly\nOTHER=opaque-fixture\nPROVENANCE_ROOTFS=/old\n'
    g.write_new(config,old)
    new=base/'next.env'
    values={'PROVENANCE_RUNSC_PATH':str(dest/'runsc'),'PROVENANCE_ROOTFS':str(dest/'rootfs'),
            'PROVENANCE_ROOTFS_IDENTITY':'sha256:'+h,'PROVENANCE_MEASURED_RUNTIME_MODE':'embedded-executable',
            'PROVENANCE_GVISOR_CGROUP_DRIVER':'systemd-user',
            'PROVENANCE_MEASURED_ROOTFS_IMAGE':str(dest/'image'),'PROVENANCE_MEASURED_LOOP_DEVICE':str(dest/'loop')}
    g.write_new(new,b'# retained exactly\nOTHER=opaque-fixture\n'+''.join(k+'='+v+'\n' for k,v in values.items()).encode())
    def pin(path):return {'path':str(path),'sha256':g.fingerprint(path)['sha256']}
    for source,name in (('/tmp/measured-runner','runner'),('/tmp/runsc','runsc')):
        shutil.copyfile(source,base/name)
        (base/name).chmod(0o555)
    p={'generation':str(dest),'uid':1001,'gid':1001,'runner':pin(base/'runner'),
       'runsc':pin(base/'runsc'),'image':pin(image),'currentConfig':pin(config),'newConfig':pin(new)}
    unit=base/'runtime.service'
    oldunit=('[Service]\nEnvironmentFile='+str(config)+'\nExecStart='+str(base/'runner')+' connect\n').encode()
    g.write_new(unit,oldunit)
    nextunit=base/'next.service'
    g.write_new(nextunit,oldunit.replace(str(base/'runner').encode(),str(dest/'runner').encode()))
    p.update({'unit':pin(unit),'newUnit':pin(nextunit),'currentRunner':pin(base/'runner')})
    identity='a'*64
    owned.append(dict(p))
    checkpoints=[]
    # Inject mount failure after owned loop/node allocation. No auto-adoption;
    # explicit recovery detaches only the exact newly allocated generation.
    original=g.run
    def fail_mount(*args):
        if args[0]=='mount':raise g.Refusal('injected fixture failure')
        return original(*args)
    with patch.object(g,'run',side_effect=fail_mount):refuse(lambda:g.install(p,identity))
    check((dest/'pending.json').exists())
    refuse(lambda:g.install(p,identity))
    g.detach(p,identity,True)
    check(not original('losetup','--noheadings','--output','NAME','--associated',str(dest/'image')))
    checkpoints.append('partial-mount-failure-owned-recovery')
    original_write=g.write_new
    for stage in ('previous.env','allocated.json','state.json','private-node'):
        parent=base/('failure-'+stage)
        parent.mkdir(mode=0o711)
        failure_dest=parent/dest.name
        env=base/('failure-'+stage+'.env')
        unit_input=base/('failure-'+stage+'.service')
        g.write_new(env,new.read_bytes().replace(str(dest).encode(),str(failure_dest).encode()))
        g.write_new(unit_input,nextunit.read_bytes().replace(str(dest).encode(),str(failure_dest).encode()))
        failure_plan=p|{'generation':str(failure_dest),'newConfig':pin(env),'newUnit':pin(unit_input)}
        owned.append(failure_plan)
        def fail_write(path,*args,**kwargs):
            if Path(path).name==stage:raise g.Refusal('injected journal fault')
            return original_write(path,*args,**kwargs)
        if stage=='private-node':
            with patch.object(g.os,'mknod',side_effect=g.Refusal('injected node fault')):
                refuse(lambda:g.install(failure_plan,identity))
        else:
            with patch.object(g,'write_new',side_effect=fail_write):
                refuse(lambda:g.install(failure_plan,identity))
        g.detach(failure_plan,identity,True)
        checkpoints.append('owned-recovery-after-'+stage)
    # Retain interrupted generation untouched. Use a separate exact parent for
    # successful installation; never erase/adopt interrupted generation state.
    parents=base/'accepted-generations'
    parents.mkdir(mode=0o711)
    newdest=parents/dest.name
    p['generation']=str(newdest)
    newbytes=new.read_bytes().replace(str(dest).encode(),str(newdest).encode())
    other=base/'accepted-next.env'
    g.write_new(other,newbytes)
    p['newConfig']=pin(other)
    otherunit=base/'accepted-next.service'
    g.write_new(otherunit,nextunit.read_bytes().replace(str(dest).encode(),str(newdest).encode()))
    p['newUnit']=pin(otherunit)
    owned.append(dict(p))
    dest=newdest
    g.install(p,identity)
    g.verify(p,identity)
    g.install(p,identity)
    checkpoints.append('installed-verified-idempotent')
    child=subprocess.Popen(['sleep','30'],cwd=dest/'rootfs')
    try:refuse(lambda:g.detach(p,identity))
    finally:
        child.terminate()
        child.wait(timeout=5)
    g.verify(p,identity)
    checkpoints.append('busy-mount-refusal')
    os.chmod(dest/'loop',0o444)
    refuse(lambda:g.verify(p,identity))
    os.chmod(dest/'loop',0o440)
    os.chmod(dest/'image',0o664)
    refuse(lambda:g.verify(p,identity))
    os.chmod(dest/'image',0o440)
    g.verify(p,identity)
    checkpoints.append('private-node-and-image-mode-refusal')
    foreign=dest/'foreign'
    g.write_new(foreign,b'unrelated fixture')
    refuse(lambda:g.detach(p,identity))
    foreign.unlink()
    checkpoints.append('foreign-resource-refusal')
    reload_state={'needed':True,'calls':0}
    def systemd_fixture(*args):
        if args==('systemctl','daemon-reload'):
            reload_state['calls']+=1;reload_state['needed']=False;return ''
        if args[0]=='systemctl':
            check(args[1]=='show' and args[-2]=='--property=NeedDaemonReload')
            return 'yes' if reload_state['needed'] else 'no'
        return original(*args)
    original_replace=g.replace_file
    def unit_write_failure(path,*args):
        if str(path)==str(unit):raise g.Refusal('injected unit replacement failure')
        return original_replace(path,*args)
    with patch.object(g,'replace_file',side_effect=unit_write_failure):
        refuse(lambda:g.select(p,identity))
    check(config.read_bytes()==newbytes and unit.read_bytes()==oldunit)
    checkpoints.append('mixed-config-unit-replacement-recovery')
    # Crash/reload loss after both replacements never starts a service. Retry
    # must tolerate the exact mixed/selected pair, but no third identity.
    def reload_failure(*args):
        if args==('systemctl','daemon-reload'):raise g.Refusal('injected reload failure')
        return systemd_fixture(*args)
    with patch.object(g,'run',side_effect=reload_failure):refuse(lambda:g.select(p,identity))
    check(config.read_bytes()==newbytes and unit.read_bytes()==otherunit.read_bytes())
    with patch.object(g,'run',side_effect=systemd_fixture):
        g.select(p,identity)
        check(reload_state=={'needed':False,'calls':1})
        check(config.read_bytes()==newbytes and unit.read_bytes()==otherunit.read_bytes())
        g.select(p,identity)
        check(reload_state['calls']==1)
    reload_state['needed']=True
    with patch.object(g,'run',side_effect=reload_failure):refuse(lambda:g.rollback(p,identity))
    check(unit.read_bytes()==oldunit and config.read_bytes()==old)
    with patch.object(g,'run',side_effect=systemd_fixture):g.rollback(p,identity)
    check(reload_state=={'needed':False,'calls':2})
    check(config.read_bytes()==old)
    with patch.object(g,'run',side_effect=systemd_fixture):g.rollback(p,identity)
    check(unit.read_bytes()==oldunit)
    check(reload_state['calls']==2)
    checkpoints.append('exact-config-select-drained-rollback-idempotent')
    failure_matrix(base,image)
    cli_tests(base,image)
    cleanup_owned()
    observed[:] = [checked_absent({'generation':row['generation']}) for row in observed]
    observed.extend(checked_absent(value) for value in owned)
    check(observed)
    cleanup_pass=all(not row['associatedLoops'] and not row['mounted'] for row in observed)
    print(json.dumps({'version':1,'generationTests':checkpoints,
                      'serviceLifecycle':'not-exercised-container-has-no-systemd',
                      'remoteDrain':'not-inferred-or-contacted','cleanupObservations':observed,
                      'allOwnedLoopsDetached':cleanup_pass}))


if __name__=='__main__':main(Path(sys.argv[1]))
