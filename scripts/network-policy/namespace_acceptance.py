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
    parser.add_argument('--sentry',action='store_true')
    args=parser.parse_args()
    assert re.fullmatch(r'sha256:[0-9a-f]{64}',args.image), 'exact local fixture image required'
    root=Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix='provenance-namespace-fixture-') as temporary:
        binary=Path(temporary)/'namespace.test'
        subprocess.run([args.go,'test','-c','-o',str(binary),'./internal/networkpolicy'],cwd=root,env=os.environ|{'CGO_ENABLED':'0'},check=True,timeout=180)
        # CI deliberately uses umask 077. Mapped non-root children execute this
        # public fixture binary too; do not inherit a root-only build mode.
        binary.chmod(0o555)
        container='provenance-namespace-fixture-'+uuid.uuid4().hex
        try:
            extra=['--cap-add','CHOWN','--cap-add','NET_RAW','-e','PROVENANCE_DISPOSABLE_SENTRY_FIXTURE=1'] if args.sentry else []
            subprocess.run(['docker','create','--name',container,'--network','none','--memory','512m' if args.sentry else '128m','--cpus','1','--pids-limit','256' if args.sentry else '128',
                '--cap-drop','ALL','--cap-add','SYS_ADMIN','--cap-add','NET_ADMIN','--cap-add','SETUID','--cap-add','SETGID','--cap-add','SYS_PTRACE',
                '--security-opt','apparmor=unconfined','--security-opt','seccomp=unconfined',
                '-e','PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1',*extra,'--entrypoint','sleep',args.image,'180'],check=True,stdout=subprocess.DEVNULL,timeout=15)
            subprocess.run(['docker','cp',str(binary),container+':/namespace.test'],check=True,timeout=15)
            subprocess.run(['docker','start',container],check=True,stdout=subprocess.DEVNULL,timeout=15)
            selection='^Test(RetainedRouteSentryActuation|AuthorityRouteSentryWithdrawal|AuthorityRouteSentryExpiry)$' if args.sentry else '^Test(MappedChildNamespaceKernelOwnership|RetainedRouteKernelActuation)$'
            result=subprocess.run(['docker','exec',container,'/namespace.test','-test.v','-test.run='+selection,'-test.count=3','-test.timeout=150s' if args.sentry else '-test.timeout=45s'],capture_output=True,text=True,timeout=160 if args.sentry else 55)
            assert len(result.stdout)<=65536 and len(result.stderr)<=65536, 'bounded namespace report exceeded'
            if result.returncode:
                raise RuntimeError('disposable namespace fixture failed: '+result.stdout[-8192:]+result.stderr[-1024:])
            assert '--- SKIP:' not in result.stdout, 'namespace acceptance must not skip'
            if args.sentry:
                assert result.stdout.count('--- PASS: TestRetainedRouteSentryActuation ')==3, 'required live native actuation case missing'
                for case in ('AuthorityRouteSentryWithdrawal','AuthorityRouteSentryExpiry'):
                    assert result.stdout.count('--- PASS: Test'+case+' ')==3, 'required live authority case missing'
                print(json.dumps({'retainedRouteLiveSentry':True,'establishedFlowsSurviveRenewal':True,'establishedAndNewFlowsDeniedAfterWithdrawal':True,'liveEndpointDuringWithdrawal':True,'ownedFirewallRemoved':True,'currentAuthorityDeadlineReduction':True,'currentAuthorityWithdrawalAndExpiry':True,'withdrawnAuthorityCannotResume':True,'repetitions':3},sort_keys=True))
                return
            cases=('retained-job-and-living-child','wrong-mapping','inherited-controller-network','not-direct-child','close-references-only','supplementary-group-refused')
            for case in cases:
                assert result.stdout.count('--- PASS: TestMappedChildNamespaceKernelOwnership/'+case+' ')==3, 'required namespace case missing'
            for case in ('install-renew-withdraw','cleanup-after-child-exit'):
                assert result.stdout.count('--- PASS: TestRetainedRouteKernelActuation/'+case+' ')==3, 'required retained actuation case missing'
            print(json.dumps({'retainedKernelNamespaceIdentity':True,'exitedChildDenied':True,'wrongJobAndMappingDenied':True,'controllerNamespaceDenied':True,'foreignParentDenied':True,'supplementaryGroupDenied':True,'referenceCleanupOnly':True,'refusedCaptureNoDescriptorLeak':True,'retainedRouteInstallRefreshCleanup':True,'cleanupAfterRouterExit':True,'controllerFirewallUnchanged':True,'replacedToolPathNotReopened':True,'repetitions':3},sort_keys=True))
        finally:
            subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)


if __name__=='__main__':
    main()
