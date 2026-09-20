#!/usr/bin/env python3
"""Real udev link setup in an explicitly disposable, networkless root guest."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess

s = importlib.util.spec_from_file_location('launch', Path(__file__).with_name('measured-service-launch.py'))
launch = importlib.util.module_from_spec(s)
s.loader.exec_module(launch)


def run(*args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=15)
    assert r.returncode == 0, (args, r.stderr[-1200:])
    return r.stdout


def probe(name, protected):
    run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'fixturepeer')
    try:
        path = Path('/sys/class/net') / name
        before = (path / 'address').read_text().strip()
        selected = run('udevadm', 'test-builtin', '--action=add', 'net_setup_link', str(path))
        after = (path / 'address').read_text().strip()
        assert (before == after) == protected, selected
        assert ('ID_NET_LINK_FILE=' + str(launch.UPLINK_LINK) + '\n' in selected) == protected
        # A second change event must also leave an owned identity intact.
        run('udevadm', 'test-builtin', '--action=change', 'net_setup_link', str(path))
        assert (path / 'address').read_text().strip() == after
    finally:
        run('ip', 'link', 'delete', name)


def main():
    assert os.geteuid() == 0 and Path('/.dockerenv').is_file()
    assert len(json.loads(run('ip', '-j', 'link'))) == 1
    assert not launch.UPLINK_LINK.exists()
    probe('ph0123456789abc', False)
    launch.UPLINK_LINK.parent.mkdir(parents=True, exist_ok=True)
    with launch.UPLINK_LINK.open('xb') as f:
        f.write(launch.uplink_link_bytes())
    launch.UPLINK_LINK.chmod(0o644)
    try:
        launch.verify_uplink_link()
        for name in ('ph0123456789abc', 'phabcdef0123456', 'ph9999999999999'):
            probe(name, True)
        for name in ('phfixture', 'ph0123456789ab', 'px0123456789abc'):
            probe(name, False)
        launch.UPLINK_LINK.write_bytes(launch.uplink_link_bytes().replace(b'none', b'persistent'))
        try:
            launch.verify_uplink_link()
        except launch.g.Refusal:
            pass
        else:
            raise AssertionError('altered policy accepted')
    finally:
        launch.UPLINK_LINK.unlink()
    assert len(json.loads(run('ip', '-j', 'link'))) == 1
    print(json.dumps({'defaultPolicyMutationReproduced': True,
        'ownedIdentitiesPreserved': 3, 'unrelatedInterfacesUnchangedByRule': 3,
        'alteredRuleRefused': True, 'allFixtureLinksRemoved': True}))


if __name__ == '__main__':
    main()
