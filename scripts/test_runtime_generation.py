import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace


def module(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


g=module('runtime-generation')
s=module('prepare-ubuntu-measured-source')


class GenerationTests(unittest.TestCase):
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
