import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import json
import io
import os
import subprocess
import sys


def module(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


g=module('runtime-generation')
s=module('prepare-ubuntu-measured-source')
b=module('runtime-generation-profile-binding')


class GenerationTests(unittest.TestCase):
    def test_replace_write_flush_and_sync_failures_preserve_original_and_retry(self):
        real_fdopen=g.os.fdopen
        class FailingOutput:
            def __init__(self,fd,mode,failure):self.file=real_fdopen(fd,mode);self.failure=failure
            def __enter__(self):return self
            def __exit__(self,*args):self.file.close()
            def write(self,data):
                if self.failure=='write':self.file.write(data[:2]);raise OSError('partial write')
                return self.file.write(data)
            def flush(self):
                if self.failure=='flush':raise OSError('flush failure')
                return self.file.flush()
            def fileno(self):return self.file.fileno()
        for failure in ('write','flush','fsync'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'current.env';path.write_bytes(b'old')
                digest=g.hashlib.sha256(b'old').hexdigest()
                temp=path.parent/'.current.env.runtime-generation'
                injection=(patch.object(g.os,'fsync',side_effect=OSError('sync failure')) if failure=='fsync' else
                           patch.object(g.os,'fdopen',side_effect=lambda fd,mode:FailingOutput(fd,mode,failure)))
                with patch.object(g,'protected',side_effect=lambda value,*args:Path(value)):
                    with injection,self.assertRaises(OSError):g.replace_file(path,digest,b'new')
                    self.assertEqual(path.read_bytes(),b'old');self.assertFalse(temp.exists())
                    g.replace_file(path,digest,b'new');self.assertEqual(path.read_bytes(),b'new')

    def test_replace_substituted_or_missing_temp_never_deletes_foreign_data(self):
        real_fchown=g.os.fchown
        for missing in (False,True):
            with self.subTest(missing=missing),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'current.env';path.write_bytes(b'old')
                foreign=Path(directory)/'foreign';foreign.write_bytes(b'unrelated')
                temp=path.parent/'.current.env.runtime-generation'
                def substitute(*args):
                    real_fchown(*args);temp.unlink()
                    if not missing:temp.symlink_to(foreign)
                with patch.object(g,'protected',side_effect=lambda value,*args:Path(value)),\
                     patch.object(g.os,'fchown',side_effect=substitute),self.assertRaises((g.Refusal,FileNotFoundError)):
                    g.replace_file(path,g.hashlib.sha256(b'old').hexdigest(),b'new')
                self.assertEqual(path.read_bytes(),b'old');self.assertEqual(foreign.read_bytes(),b'unrelated')
                self.assertEqual(temp.is_symlink(),not missing)

    def test_replace_post_rename_sync_failure_keeps_selected_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'current.env';path.write_bytes(b'old')
            real_sync=g.sync_directory;calls=[]
            def sync(value):
                calls.append(value)
                if len(calls)==2:raise OSError('post-rename sync failure')
                real_sync(value)
            with patch.object(g,'protected',side_effect=lambda value,*args:Path(value)):
                with patch.object(g,'sync_directory',side_effect=sync),self.assertRaises(OSError):
                    g.replace_file(path,g.hashlib.sha256(b'old').hexdigest(),b'new')
                self.assertEqual(path.read_bytes(),b'new')
                self.assertFalse((path.parent/'.current.env.runtime-generation').exists())
                g.replace_file(path,g.hashlib.sha256(b'new').hexdigest(),b'new')

    def test_replace_metadata_failure_cleans_only_owned_temp_and_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'current.env';path.write_bytes(b'old')
            digest=g.hashlib.sha256(b'old').hexdigest()
            temp=path.parent/'.current.env.runtime-generation'
            with patch.object(g,'protected',side_effect=lambda value,*args:Path(value)):
                with patch.object(g.os,'fchown',side_effect=OSError('injected metadata failure')):
                    with self.assertRaises(OSError):g.replace_file(path,digest,b'new')
                self.assertEqual(path.read_bytes(),b'old')
                self.assertFalse(temp.exists())
                g.replace_file(path,digest,b'new')
                self.assertEqual(path.read_bytes(),b'new')
                temp.write_bytes(b'foreign-owned-before-invocation')
                with self.assertRaises(FileExistsError):g.replace_file(path,g.hashlib.sha256(b'new').hexdigest(),b'again')
                self.assertEqual(temp.read_bytes(),b'foreign-owned-before-invocation')
                self.assertEqual(path.read_bytes(),b'new')

    def test_legacy_tar_failure_and_digest_drift(self):
        p={'legacyRootfs':{'path':'/fixture','treeSha256':'a'*64}}
        for status in (0,2):
            process=SimpleNamespace(stdout=io.BytesIO(b'fixture tree'),wait=lambda timeout:status)
            with patch.object(g,'mount_info',return_value={'options':'ro,nodev'}),\
                 patch.object(g.subprocess,'Popen',return_value=process),self.assertRaises(g.Refusal):g.legacy(p)

    def test_main_rechecks_drain_after_legacy_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            p={'generation':str(Path(directory)/'generation')}
            order=[]
            def drained(*args):
                order.append('drain')
                if len(order)==3:raise g.Refusal('expired while checking legacy')
            args=['operator','install','--plan','unused','--plan-sha256','a'*64,'--drain','unused','--drain-sha256','b'*64]
            with patch.object(g.sys,'argv',args),patch.dict(g.os.environ),patch.object(g.os,'geteuid',return_value=0),\
                 patch.object(g,'load_plan',return_value=p),patch.object(g,'protected',side_effect=lambda value,*args:Path(value)),\
                 patch.object(g,'legacy',side_effect=lambda p:order.append('legacy')),\
                 patch.object(g,'drained',side_effect=drained),patch.object(g,'install') as install:
                with self.assertRaises(g.Refusal):g.main()
                install.assert_not_called()
            self.assertEqual(order,['drain','legacy','drain'])

    def test_ci_requires_observed_cleanup_and_complete_failure_matrix(self):
        driver=Path(__file__).with_name('test-runtime-generation-ci.sh').read_text()
        code=driver.split('python3 - "$evidence/fixture.log" <<\'PY\'\n',1)[1].split('\nPY\n',1)[0]
        passes='\n'.join('--- PASS: TestRuntimeMountFixture/'+name for name in ('wrong-image-inode','writable-image','executable-symlink','not-squashfs'))+'\n--- PASS: TestMeasuredPreflightWithProtectedImageFiles\n'
        row={'associatedLoops':[],'mounted':False}
        records=[{'failureMatrix':[{'stage':str(i),'injectionReached':True,'postCleanup':row} for i in range(45)]},
                 {'cliTests':['full-cli-install-verify-select-rollback-idempotence','full-cli-journalled-recovery']},
                 {'cleanupObservations':[row],'allOwnedLoopsDetached':True}]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture.log'
            def run(values):
                path.write_text(passes+'\n'.join(json.dumps(x) for x in values))
                return subprocess.run([sys.executable,'-',str(path)],input=code,text=True,capture_output=True).returncode
            self.assertEqual(run(records),0)
            self.assertNotEqual(run([{'allOwnedLoopsDetached':True}]),0)
            bad=json.loads(json.dumps(records));bad[-1]['cleanupObservations'][0]['associatedLoops']=['/dev/loop999']
            self.assertNotEqual(run(bad),0)
            self.assertNotEqual(run(records[1:]),0)

    def test_profile_binding_exact_identity_and_exclusive_group(self):
        path='/var/lib/provenance-measurement-ci.ABCDef12/gvisor-smoke.test'
        expected={'path':path,'device':1,'inode':2,'sha256':'a'*64,'owner':0,'group':62001,'mode':0o550}
        with tempfile.TemporaryDirectory() as d:
            record=Path(d)/'binding.json'
            record.write_text(json.dumps({'version':1,'uid':62001,'gid':62001,'executable':expected}))
            args=['binding','verify',path,'62001','62001',str(record)]
            with patch.object(b.sys,'argv',args),patch.object(b.os,'geteuid',return_value=0),\
                 patch.object(b.grp,'getgrgid',return_value=SimpleNamespace(gr_mem=[])),\
                 patch.object(b.pwd,'getpwall',return_value=[SimpleNamespace(pw_uid=62001,pw_gid=62001)]),\
                 patch.object(b.Path,'lstat',return_value=SimpleNamespace(st_gid=62001,st_mode=0o40710)),\
                 patch.object(b,'identity',return_value=expected) as identity:
                b.main()
                for key,value in [('inode',3),('sha256','b'*64),('group',62002),('path',path+'x')]:
                    identity.return_value=expected|{key:value}
                    with self.subTest(key=key),self.assertRaises(AssertionError):b.main()
                identity.return_value=expected
                with patch.object(b.grp,'getgrgid',return_value=SimpleNamespace(gr_mem=['foreign'])),self.assertRaises(AssertionError):b.main()
                with patch.object(b.pwd,'getpwall',return_value=[SimpleNamespace(pw_uid=62002,pw_gid=62001)]),self.assertRaises(AssertionError):b.main()

    def plan(self):
        return {'generation':'/var/lib/example/sha256-'+'a'*64,'image':{'sha256':'a'*64}}

    def new(self):
        p=self.plan()
        d=p['generation']
        values={'PROVENANCE_RUNSC_PATH':d+'/runsc','PROVENANCE_ROOTFS':d+'/rootfs',
                'PROVENANCE_ROOTFS_IDENTITY':'sha256:'+'a'*64,
                'PROVENANCE_MEASURED_RUNTIME_MODE':'embedded-executable',
                'PROVENANCE_GVISOR_CGROUP_DRIVER':'systemd-user',
                'PROVENANCE_MEASURED_ROOTFS_IMAGE':d+'/image',
                'PROVENANCE_MEASURED_LOOP_DEVICE':d+'/loop'}
        return b'# retained\nOTHER=opaque-fixture\n'+''.join(k+'='+v+'\n' for k,v in values.items()).encode()

    def test_config_exact_delta(self):
        g.config_delta(self.plan(),b'# retained\nOTHER=opaque-fixture\nPROVENANCE_ROOTFS=/old\n',self.new())

    def test_config_refuses_unrelated_duplicate_shell_and_path(self):
        for data in (self.new().replace(b'opaque-fixture',b'changed'),
                     self.new()+b'PROVENANCE_ROOTFS=/foreign\n',
                     self.new().replace(b'/runsc\n',b'/runsc;id\n'),
                     self.new().replace(b'embedded-executable',b'unknown'),
                     self.new().replace(b'OTHER=',b'export OTHER=')):
            with self.subTest(data=len(data)),self.assertRaises(g.Refusal):
                g.config_delta(self.plan(),b'# retained\nOTHER=opaque-fixture\n',data)

    def test_drain_rejects_stale_incomplete_and_wrong_plan(self):
        base={'version':1,'planSha256':'a'*64,'issuedAt':1000,'expiresAt':1200,
              'platformDrainEvidenceSha256':'b'*64,'activeLeases':0,'pendingTerminalReplay':0}
        for delta in ({'expiresAt':1001},{'activeLeases':1},{'pendingTerminalReplay':1},
                      {'planSha256':'c'*64},{'issuedAt':1200},{'expiresAt':9999},
                      {'platformDrainEvidenceSha256':''},{'activeLeases':False}):
            with patch.object(g,'read_json',return_value=base|delta),patch.object(g.time,'time',return_value=1100):
                with self.subTest(delta=delta),self.assertRaises(g.Refusal):
                    g.drained({},'a'*64,'unused','unused')

    def test_unit_exact_binary_only_delta(self):
        p=self.plan()|{'currentRunner':{'path':'/opt/old-runner'},'currentConfig':{'path':'/etc/example.env'}}
        old=b'[Service]\nEnvironmentFile=/etc/example.env\nExecStart=/opt/old-runner connect --config=x\n'
        new=old.replace(b'/opt/old-runner',(p['generation']+'/runner').encode())
        g.unit_delta(p,old,new)
        for value in (new+b'ExecStart=/foreign\n',new.replace(b'connect',b'execute'),
                      new.replace(b'ExecStart=',b' ExecStart='),new.replace(b'--config=x',b'--config=%i')):
            with self.assertRaises(g.Refusal):g.unit_delta(p,old,value)

    def test_drain_checks_unit_manager_and_process_identity(self):
        d={'version':1,'planSha256':'a'*64,'issuedAt':1000,'expiresAt':1200,
           'platformDrainEvidenceSha256':'b'*64,'activeLeases':0,'pendingTerminalReplay':0}
        p={'uid':1001,'gid':1001,'unit':{'path':'/etc/systemd/system/runtime.service'}}
        values={'FragmentPath':p['unit']['path'],'DropInPaths':'','User':'1001','Group':'1001',
                'ActiveState':'inactive'}
        def invoke(*args):return values[args[-2].split('=')[1]]
        with patch.object(g,'read_json',return_value=d),patch.object(g.time,'time',return_value=1100),\
             patch.object(g,'run',side_effect=invoke),patch.object(g.Path,'iterdir',return_value=[]):
            g.drained(p,'a'*64,'unused','unused')
            for key,value in [('FragmentPath','/foreign'),('DropInPaths','/dropin'),('User','0'),
                              ('Group','0'),('ActiveState','active')]:
                old=values[key]
                values[key]=value
                with self.assertRaises(g.Refusal):g.drained(p,'a'*64,'unused','unused')
                values[key]=old
            entry=SimpleNamespace(name='123',stat=lambda:SimpleNamespace(st_uid=1001))
            with patch.object(g.Path,'iterdir',return_value=[entry]),self.assertRaises(g.Refusal):
                g.drained(p,'a'*64,'unused','unused')

    def test_symlink_and_unprotected_ancestry_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file'
            p.write_bytes(b'x')
            q=Path(d)/'link'
            q.symlink_to(p)
            for value in (p,q,Path('/')):
                with self.assertRaises(g.Refusal):
                    g.protected(value)

    def test_normalizer_refuses_unexpected_links_and_nonempty_placeholder(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for name,kind in s.EMPTY.items():
                p=root/name
                p.parent.mkdir(parents=True,exist_ok=True)
                p.mkdir() if kind=='directory' else p.write_bytes(b'')
            import os
            for pair in s.LINKS:
                a,b=sorted(pair)
                (root/a).parent.mkdir(parents=True,exist_ok=True)
                (root/a).write_bytes(a.encode())
                os.link(root/a,root/b)
            self.assertEqual(len(s.inspect(root)),2)
            p=root/'dev/console'
            p.write_bytes(b'not-empty')
            with self.assertRaises(ValueError): s.inspect(root)
            p.write_bytes(b'')
            os.link(root/'usr/bin/perl',root/'unexpected')
            with self.assertRaises(ValueError): s.inspect(root)


if __name__=='__main__':
    unittest.main()
