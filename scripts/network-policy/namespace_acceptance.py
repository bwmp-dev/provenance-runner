#!/usr/bin/env python3
"""Retained kernel namespace ownership in a fresh no-network container only."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True)
    parser.add_argument('--go',default='go')
    args=parser.parse_args()
    assert re.fullmatch(r'sha256:[0-9a-f]{64}',args.image), 'exact local fixture image required'
    root=Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix='provenance-namespace-fixture-') as temporary:
        binary=Path(temporary)/'namespace.test'
        subprocess.run([args.go,'test','-c','-o',str(binary),'./internal/networkpolicy'],cwd=root,env=os.environ|{'CGO_ENABLED':'0'},check=True,timeout=180)
        container='provenance-namespace-fixture-'+uuid.uuid4().hex
        try:
            subprocess.run(['docker','create','--name',container,'--network','none','--memory','128m','--cpus','1','--pids-limit','128',
                '--cap-drop','ALL','--cap-add','SYS_ADMIN','--cap-add','SETUID','--cap-add','SETGID','--cap-add','SYS_PTRACE',
                '--security-opt','apparmor=unconfined','--security-opt','seccomp=unconfined',
                '-e','PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1','--entrypoint','sleep',args.image,'120'],check=True,stdout=subprocess.DEVNULL,timeout=15)
            subprocess.run(['docker','cp',str(binary),container+':/namespace.test'],check=True,timeout=15)
            subprocess.run(['docker','start',container],check=True,stdout=subprocess.DEVNULL,timeout=15)
            result=subprocess.run(['docker','exec',container,'/namespace.test','-test.v','-test.run=^TestMappedChildNamespaceKernelOwnership$','-test.count=3','-test.timeout=30s'],capture_output=True,text=True,timeout=40)
            assert len(result.stdout)<=65536 and len(result.stderr)<=65536, 'bounded namespace report exceeded'
            if result.returncode:
                raise RuntimeError('disposable namespace fixture failed: '+result.stdout[-8192:]+result.stderr[-1024:])
            assert '--- SKIP:' not in result.stdout, 'namespace acceptance must not skip'
            cases=('retained-job-and-living-child','wrong-mapping','inherited-controller-network','not-direct-child','close-references-only','supplementary-group-refused')
            for case in cases:
                assert result.stdout.count('--- PASS: TestMappedChildNamespaceKernelOwnership/'+case+' ')==3, 'required namespace case missing'
            print(json.dumps({'retainedKernelNamespaceIdentity':True,'exitedChildDenied':True,'wrongJobAndMappingDenied':True,'controllerNamespaceDenied':True,'foreignParentDenied':True,'supplementaryGroupDenied':True,'referenceCleanupOnly':True,'refusedCaptureNoDescriptorLeak':True,'repetitions':3},sort_keys=True))
        finally:
            subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)


if __name__=='__main__':
    main()
