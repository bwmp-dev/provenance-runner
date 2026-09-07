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
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('generation','/repo/scripts/runtime-generation.py')
g=importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
owned=[]


def cleanup_owned():
    for p in reversed(owned):
        dest=Path(p['generation'])
        if dest.exists():
            try:g.detach(p,'a'*64,(dest/'pending.json').exists())
            except Exception:
                print('FIXTURE CLEANUP INCOMPLETE: retain container for diagnosis',file=sys.stderr)
                os._exit(1)


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
    def systemd_fixture(*args):
        if args[0]=='systemctl':return 'no' if args[1]=='show' else ''
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
        check(config.read_bytes()==newbytes and unit.read_bytes()==otherunit.read_bytes())
        g.select(p,identity)
        g.rollback(p,identity)
    check(config.read_bytes()==old)
    with patch.object(g,'run',side_effect=systemd_fixture):g.rollback(p,identity)
    check(unit.read_bytes()==oldunit)
    checkpoints.append('exact-config-select-drained-rollback-idempotent')
    print(json.dumps({'version':1,'generationTests':checkpoints,
                      'serviceLifecycle':'not-exercised-container-has-no-systemd',
                      'remoteDrain':'not-inferred-or-contacted','allOwnedLoopsDetached':True}))


if __name__=='__main__':main(Path(sys.argv[1]))
