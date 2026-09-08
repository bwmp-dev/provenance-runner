#!/usr/bin/env python3
"""Real system-manager acceptance, only inside the exclusive disposable guest."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('baseline', '/opt/runtime-baseline.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
ROOT = Path('/var/lib/provenance-baseline-fixture')
UID = GID = 61023
CASES = []
UNITS = {}


def run(*args, ok=True):
    r = subprocess.run(args, capture_output=True, text=True, timeout=45)
    assert not ok or r.returncode == 0, (args[0], r.returncode, r.stderr)
    return r


def write(path, data, mode=0o600):
    with path.open('xb') as stream:
        stream.write(data)
    path.chmod(mode)
    return {'path': str(path), 'sha256': b.digest(data)}


def fixture(name):
    base = ROOT / name
    base.mkdir(mode=0o755)
    sources = base / 'sources'
    sources.mkdir(mode=0o700)
    destination = str(base / 'installed')
    state = str(base / 'state')
    unit = '/etc/systemd/system/provenance-runner-' + name + '.service'
    p = dict(version=1, uid=UID, gid=GID, destination=destination,
             stateDirectory=state, unitDestination=unit)
    p['runner'] = write(sources / 'runner', Path('/usr/bin/true').read_bytes(), 0o555)
    runsc = write(base / 'runsc', Path('/usr/bin/true').read_bytes(), 0o555)
    rootfs = base / 'legacy'
    rootfs.mkdir(mode=0o755)
    write(rootfs / 'synthetic', b'harmless synthetic legacy tree\n', 0o444)
    run('/usr/bin/mount', '--bind', str(rootfs), str(rootfs))
    run('/usr/bin/mount', '-o', 'remount,bind,ro', str(rootfs))
    tree = subprocess.run(['/usr/bin/tar', '--sort=name', '--format=gnu', '--mtime=@0',
                           '--owner=0', '--group=0', '--numeric-owner', '-cf', '-', '-C', str(rootfs), '.'],
                          capture_output=True, check=True).stdout
    env = dict(PROVENANCE_RUNSC_PATH=runsc['path'], PROVENANCE_ROOTFS=str(rootfs),
               PROVENANCE_ROOTFS_IDENTITY='sha256:' + b.digest(tree),
               PROVENANCE_PAPER_PROBE_URI='https://fixture.invalid/probe.jar',
               PROVENANCE_PAPER_PROBE_SHA256='1' * 64, PROVENANCE_PAPER_PROBE_SIZE_BYTES='1',
               PROVENANCE_PAPER_PREPARED_RUNTIME_URI='https://fixture.invalid/runtime.tar',
               PROVENANCE_PAPER_PREPARED_RUNTIME_SHA256='2' * 64,
               PROVENANCE_PAPER_PREPARED_RUNTIME_SIZE_BYTES='2',
               PROVENANCE_PAPER_PREPARED_RUNTIME_MAX_EXPANDED_BYTES='4096',
               PROVENANCE_ARTIFACT_HOSTS='fixture.invalid')
    for key in ('WORKSPACE_ROOT', 'CACHE_ROOT', 'GVISOR_STATE_ROOT', 'GVISOR_BUNDLE_ROOT'):
        path = base / key.lower()
        path.mkdir(mode=0o700)
        os.chown(path, UID, GID)
        env['PROVENANCE_' + key] = str(path)
    p['environment'] = write(sources / 'environment', ''.join(k + '=' + v + '\n' for k, v in env.items()).encode())
    runtime = dict(version=1, runsc=runsc, legacyRootfs=dict(path=str(rootfs), treeSha256=b.digest(tree)),
                   environment=env, downloads=[dict(prefix=prefix, uri=env[prefix + '_URI'],
                     sha256=env[prefix + '_SHA256'], sizeBytes=int(env[prefix + '_SIZE_BYTES']))
                     for prefix in ('PROVENANCE_PAPER_PROBE', 'PROVENANCE_PAPER_PREPARED_RUNTIME')])
    p['runtime'] = write(sources / 'runtime.json', b.encoded(runtime))
    p['credential'] = write(sources / 'credential', b'synthetic-only-not-a-real-credential')
    runner_id = '00000000-0000-0000-0000-000000000001'
    organization_id = '00000000-0000-0000-0000-000000000002'
    p['identity'] = write(sources / 'identity.json', b.encoded(dict(phase='active', runnerId=runner_id,
                         organizationId=organization_id, response=dict(credentialSha256=p['credential']['sha256']))))
    p['connect'] = write(sources / 'connect.json', b.encoded(dict(
        schemaVersion='provenance.runner-connect/v1alpha1', gatewayAddress='fixture.invalid:443',
        runnerId=runner_id, instanceId='synthetic', credentialFile='credential', identityKeyFile='identity.json',
        expectedScope=dict(kind='organization', organizationId=organization_id),
        resources=dict(cpuMillis=1000, memoryBytes=1048576, diskBytes=1048576, processCount=32))))
    p['unit'] = write(sources / 'unit', b.unit_bytes(p))
    plan = write(sources / 'plan.json', b.encoded(p))
    print(json.dumps({'fixture': name, 'planSha256': plan['sha256'],
                      'runnerSha256': p['runner']['sha256'], 'runtimeSha256': p['runtime']['sha256'],
                      'environmentSha256': p['environment']['sha256'], 'unitSha256': p['unit']['sha256'],
                      'legacyTreeSha256': runtime['legacyRootfs']['treeSha256'],
                      'runtimeUid': UID, 'runtimeGid': GID}), flush=True)
    return p, plan


def invoke(action, plan, ok=True):
    r = run('/usr/bin/python3', '/opt/runtime-baseline.py', action, '--plan', plan['path'],
            '--plan-sha256', plan['sha256'], ok=ok)
    assert ('synthetic-only-not-a-real-credential' not in r.stdout + r.stderr)
    if not ok:
        assert r.returncode != 0, action
    return r


def remember(p):
    unit = Path(p['unitDestination'])
    if unit.exists():
        UNITS[str(unit)] = b.identity(unit)


def case(name, fn):
    fn()
    CASES.append(name)
    print(json.dumps({'case': name, 'passed': True}), flush=True)


def basic():
    p, plan = fixture('first')
    result = invoke('install', plan)
    assert json.loads(result.stdout)['status'] == 'installed-disabled-stopped'
    remember(p)
    before = {str(path): b.identity(path) for path, *_ in b.expected_objects(p, b.load_plan(plan['path'], plan['sha256'])[1])}
    assert json.loads(invoke('install', plan).stdout)['status'] == 'exact-repeat'
    invoke('verify', plan)
    ledger = Path(p['destination']) / 'ownership.jsonl'
    old_ledger = ledger.with_name('retained-ledger')
    ledger.rename(old_ledger)
    write(ledger, old_ledger.read_bytes())
    invoke('recover', plan, ok=False)
    ledger.unlink()
    old_ledger.rename(ledger)
    invoke('verify', plan)
    assert before == {path: b.identity(Path(path)) for path in before}
    v = b.manager(Path(p['unitDestination']).name)
    assert v['ActiveState'] == 'inactive' and v['UnitFileState'] == 'disabled' and v['NeedDaemonReload'] == 'no'
    # The accepted sidecar contract needs directory-level atomics under this UID.
    state = Path(p['stateDirectory'])
    run('/usr/bin/setpriv', '--reuid', str(UID), '--regid', str(GID), '--clear-groups',
        '/usr/bin/python3', '-c',
        'import os,sys; from pathlib import Path; p=Path(sys.argv[1]); '
        't=p/".journal-test"; t.write_bytes(b"{}"); os.replace(t,p/".provenance-runner-journal.json"); '
        '(p/".provenance-runner-journal.json").unlink()', str(state))
    invoke('verify', plan)
    # Replacing a byte-identical owned object with a distinct inode must fail.
    target = Path(p['destination']) / 'runner'
    old = target.with_name('runner-retained')
    target.rename(old)
    write(target, old.read_bytes(), 0o555)
    invoke('verify', plan, ok=False)
    target.unlink()
    old.rename(target)
    invoke('verify', plan)


def conflicts():
    p, plan = fixture('foreign')
    state = Path(p['stateDirectory'])
    state.mkdir()
    marker = state / 'foreign'
    write(marker, b'foreign work')
    original = b.identity(marker)
    invoke('install', plan, ok=False)
    assert b.identity(marker) == original and marker.read_bytes() == b'foreign work'
    assert not Path(p['destination']).exists()
    p, plan = fixture('fragment')
    unit = Path(p['unitDestination'])
    write(unit, b'[Service]\nExecStart=/usr/bin/true\n')
    remember(p)
    invoke('install', plan, ok=False)
    assert not Path(p['destination']).exists()


def enabled_active():
    p, plan = fixture('enabled')
    invoke('install', plan)
    remember(p)
    run('/usr/bin/systemctl', 'enable', Path(p['unitDestination']).name)
    invoke('install', plan, ok=False)
    invoke('verify', plan, ok=False)
    run('/usr/bin/systemctl', 'disable', Path(p['unitDestination']).name)
    invoke('verify', plan)
    # Only the fixture creates/starts/stops this separate harmless synthetic
    # conflicting service; the installer has no activation command surface.
    p, plan = fixture('active')
    unit = Path(p['unitDestination'])
    write(unit, b'[Service]\nExecStart=/usr/bin/sleep 60\n')
    remember(p)
    run('/usr/bin/systemctl', 'daemon-reload')
    run('/usr/bin/systemctl', 'start', unit.name)
    try:
        assert run('/usr/bin/systemctl', 'is-active', unit.name).stdout.strip() == 'active'
        invoke('install', plan, ok=False)
        assert not Path(p['destination']).exists()
    finally:
        assert b.identity(unit) == UNITS[str(unit)]
        run('/usr/bin/systemctl', 'stop', unit.name)
    p, plan = fixture('dropin')
    directory = Path(p['unitDestination'] + '.d')
    directory.mkdir()
    write(directory / 'foreign.conf', b'[Service]\nEnvironment=FOREIGN=yes\n')
    invoke('install', plan, ok=False)
    assert not Path(p['destination']).exists()


def negative_inputs():
    for name, mutate in (
        ('secretmode', lambda p: Path(p['credential']['path']).chmod(0o644)),
        ('planmode', lambda p: (Path(p['runner']['path']).parent / 'plan.json').chmod(0o644)),
        ('ancestry', lambda p: Path(p['runner']['path']).parent.chmod(0o777)),
        ('pin', lambda p: Path(p['runner']['path']).write_bytes(b'not ELF')),
        ('writabletree', lambda p: run('/usr/bin/mount', '-o', 'remount,bind,rw', str(Path(p['destination']).parent / 'legacy'))),
    ):
        p, plan = fixture(name)
        mutate(p)
        invoke('install', plan, ok=False)
        assert not Path(p['destination']).exists()
    p, plan = fixture('symlink')
    source = Path(p['runner']['path'])
    source.rename(source.with_name('actual'))
    source.symlink_to('actual')
    invoke('install', plan, ok=False)
    assert not Path(p['destination']).exists()
    p, plan = fixture('identity')
    p['gid'] = 1
    new = write(Path(plan['path']).with_name('bad-plan.json'), b.encoded(p))
    invoke('install', new, ok=False)
    assert not Path(p['destination']).exists()
    for key in ('DATABASE_URL', 'TEMPORAL_ADDRESS', 'MODRINTH_TOKEN', 'PROVENANCE_MANAGEMENT_TOKEN', 'LD_PRELOAD'):
        try:
            b.environment((key + '=synthetic\n').encode())
            raise AssertionError('forbidden environment accepted')
        except b.Refusal:
            pass


def interruption():
    # Real writes and real manager calls; fault injection changes only local
    # durability calls. No systemctl fake or manager response substitution.
    for at in (1, 2, 3, 5, 8, 12, 15, 16, 17):
        p, plan = fixture('interrupt-' + str(at))
        loaded_plan, inputs = b.load_plan(plan['path'], plan['sha256'])
        original = b.sync
        calls = 0
        def fail(path):
            nonlocal calls
            calls += 1
            if calls == at:
                raise OSError('injected durability interruption')
            original(path)
        try:
            with patch.object(b, 'sync', fail):
                b.install(loaded_plan, plan['sha256'], inputs)
        except OSError:
            assert calls == at
        else:
            raise AssertionError('fault not reached')
        remember(p)
        before = {str(path): b.identity(path) for path, *_ in b.expected_objects(p, inputs) if path.exists()}
        # Fault 17 is after the complete marker itself was durably fsynced.
        invoke('install', plan, ok=at == 17)
        result = invoke('recover', plan, ok=False) if at in (1, 3, 5, 15) else run(
            '/usr/bin/python3', '/opt/runtime-baseline.py', 'recover', '--plan', plan['path'],
            '--plan-sha256', plan['sha256'], ok=False)
        # Either exact recorded state or conservative refusal, never invented
        # resume/rollback. All originally retained inodes survive recovery.
        assert result.returncode in (0, 1)
        assert before == {path: b.identity(Path(path)) for path in before}
        v = b.manager(Path(p['unitDestination']).name)
        assert v['MainPID'] == '0' and v['ActiveState'] == 'inactive'
        print(json.dumps({'faultSync': at, 'recoveryExit': result.returncode}), flush=True)
    p, plan = fixture('reload-interrupt')
    loaded_plan, inputs = b.load_plan(plan['path'], plan['sha256'])
    original = b.command
    reached = False
    def after_reload(*args, **kwargs):
        nonlocal reached
        result = original(*args, **kwargs)
        if args == ('/usr/bin/systemctl', '--system', 'daemon-reload'):
            reached = True
            raise OSError('interrupted after actual reload')
        return result
    try:
        with patch.object(b, 'command', after_reload):
            b.install(loaded_plan, plan['sha256'], inputs)
    except OSError:
        assert reached
    else:
        raise AssertionError('reload fault not reached')
    remember(p)
    b.loaded(p)
    invoke('install', plan, ok=False)
    assert json.loads(invoke('recover', plan).stdout)['complete'] is False
    # Foreign work introduced after interruption is retained and refused.
    foreign = Path(p['destination']) / 'foreign-work'
    write(foreign, b'fixture-owned foreign marker')
    before = b.identity(foreign)
    invoke('recover', plan, ok=False)
    assert b.identity(foreign) == before


def cleanup_units():
    for path, inode in UNITS.items():
        unit = Path(path)
        v = run('/usr/bin/systemctl', 'show', unit.name, '--property=ActiveState', '--property=MainPID').stdout
        assert set(v.splitlines()) == {'ActiveState=inactive', 'MainPID=0'}
        assert b.identity(unit) == inode
        unit.unlink()
    run('/usr/bin/systemctl', '--system', 'daemon-reload')
    for path in UNITS:
        assert b.manager(Path(path).name)['LoadState'] == 'not-found'
    print(json.dumps({'exactUnitCleanup': True, 'unitCount': len(UNITS)}), flush=True)


def main():
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert Path('/run/provenance-baseline-disposable').read_text() == 'wp10a-disposable-only\n'
    assert Path('/proc/1/ns/pid').stat().st_ino == Path('/proc/self/ns/pid').stat().st_ino
    assert not ROOT.exists()
    ROOT.mkdir(mode=0o755)
    run('/usr/sbin/groupadd', '--gid', str(GID), 'pvm-baseline')
    run('/usr/sbin/useradd', '--uid', str(UID), '--gid', str(GID), '--no-create-home', 'pvm-baseline')
    case('first-install-repeat-real-reload-disabled-stopped-sidecar-atomics-inode-drift', basic)
    case('foreign-state-fragment-dropin-refusal', conflicts)
    case('enabled-active-refusal', enabled_active)
    case('path-pin-identity-secret-mode-environment-refusal', negative_inputs)
    case('durability-interruption-retention', interruption)
    case('exact-loaded-unit-cleanup', cleanup_units)
    # Mount cleanup is exclusively fixture setup, never installer behavior.
    for base in ROOT.iterdir():
        run('/usr/bin/umount', str(base / 'legacy'))
        assert run('/usr/bin/mountpoint', '--quiet', str(base / 'legacy'), ok=False).returncode == 32
    run('/usr/sbin/userdel', 'pvm-baseline')
    if run('/usr/bin/getent', 'group', str(GID), ok=False).returncode == 0:
        run('/usr/sbin/groupdel', 'pvm-baseline')
    assert run('/usr/bin/getent', 'passwd', str(UID), ok=False).returncode != 0
    assert run('/usr/bin/getent', 'group', str(GID), ok=False).returncode != 0
    print(json.dumps({'passed': CASES, 'fixtureMountsAndIdentityRemoved': True,
                      'remainingFiles': 'private guest only; exact container disposal by harness',
                      'limitation': 'synthetic pins, no runner start, cryptographic activation or Paper claim'}))


if __name__ == '__main__':
    main()
