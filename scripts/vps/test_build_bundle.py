"""Exercise the real build invocation without downloads or a runner process."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


class BuildBundleVersionTest(unittest.TestCase):
    def test_untagged_bundle_compiles_semver_and_exact_commit(self):
        source = Path(__file__).with_name('build-bundle.sh')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / 'scripts/vps/build-bundle.sh'
            script.parent.mkdir(parents=True)
            shutil.copyfile(source, script)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture',
                            '-c', 'user.email=fixture@example.invalid', 'commit',
                            '--allow-empty', '-qm', 'fixture'], check=True)
            commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
            binary = root / 'bin'
            binary.mkdir()
            # Stop at the compiler boundary: never download or execute artifacts.
            fake = binary / 'go'
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\nexit 42\n')
            fake.chmod(0o700)
            result = subprocess.run(['bash', str(script), str(root / 'bundle')],
                                    env={'PATH': str(binary) + ':' + os.defpath},
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 42, result.stderr)
            flags = result.stdout.splitlines()
            self.assertIn('build', flags)
            ldflags = flags[flags.index('-ldflags') + 1]
            match = re.search(r'buildinfo.Version=(\S+)', ldflags)
            self.assertIsNotNone(match)
            self.assertEqual(match[1], '0.0.0-dev+git.' + commit[:12])
            self.assertRegex(match[1], r'^0\.0\.0-dev\+git\.[0-9a-f]{12}$')
            self.assertIn('buildinfo.Commit=' + commit, ldflags)


if __name__ == '__main__':
    unittest.main()
