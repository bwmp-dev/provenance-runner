import pathlib
import subprocess
import tempfile
import unittest
import io
import os
import stat
import types
from unittest.mock import patch


HELPER = pathlib.Path(__file__).with_name('measured-runtime-profile.sh')


class ProfileTests(unittest.TestCase):
    def run_case(self, body):
        with tempfile.TemporaryDirectory() as directory:
            script = f'''set -eu
source "{HELPER}"
profile_file=$1/profile
profile_name=pvm-measured-AbCd1234
task_uid=61001
printf 'owned profile' > "$profile_file"
profile_sha=$(sha256sum "$profile_file"); profile_sha=${{profile_sha%% *}}
present=0 calls=
profile_present() {{ [[ "$present" == 1 ]]; }}
apparmor_parser() {{ calls="$calls $*"; case "$*" in *--add*) present=1;; *--remove*) present=0;; esac; }}
pgrep() {{ return 1; }}
timeout() {{ [[ "$1 $2" == '--kill-after=5s 15s' ]]; shift 2; "$@"; }}
{body}
'''
            result = subprocess.run(['bash', '-c', script, 'test', directory], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_add_only_remove_exact_owned_profile(self):
        self.run_case('''profile_load
[[ "$profile_loaded" == 1 && "$profile_uncertain" == 0 ]]
profile_remove
[[ "$profile_status" == removed && "$profile_loaded" == 0 ]]
[[ "$calls" == " --skip-cache --add $profile_file --skip-cache --remove $profile_file" ]]
''')

    def test_collision_and_unavailable_inventory_never_load(self):
        for setup in ('present=1', 'profile_present() { return 2; }'):
            self.run_case(setup + '''
if profile_load; then exit 9; fi
[[ -z "$calls" && "$profile_loaded" == 0 ]]
''')

    def test_failed_add_never_adopted_or_removed(self):
        self.run_case('''apparmor_parser() { calls=failed_add; present=1; return 1; }
if profile_load; then exit 9; fi
if profile_remove; then exit 8; fi
[[ "$calls" == failed_add && "$profile_uncertain" == 1 && "$profile_loaded" == 0 ]]
''')

    def test_processes_or_query_error_block_unload(self):
        for status in (0, 2):
            self.run_case(f'''profile_load
pgrep() {{ return {status}; }}
if profile_remove; then exit 9; fi
[[ "$profile_loaded" == 1 && "$calls" != *--remove* ]]
''')

    def test_parser_timeouts_retain_uncertain_or_owned_profile(self):
        self.run_case('''timeout() { return 124; }
if profile_load; then exit 9; fi
if profile_remove; then exit 8; fi
[[ "$profile_uncertain" == 1 && "$profile_status" == add_uncertain && -z "$calls" ]]
''')
        self.run_case('''profile_load
timeout() { return 124; }
if profile_remove; then exit 9; fi
[[ "$profile_loaded" == 1 && "$profile_status" == remove_failed ]]
''')

    def test_changed_source_and_failed_removal_retain_ownership(self):
        self.run_case('''profile_load
printf changed >> "$profile_file"
if profile_remove; then exit 9; fi
[[ "$profile_loaded" == 1 && "$calls" != *--remove* ]]
''')
        self.run_case('''profile_load
apparmor_parser() { return 1; }
if profile_remove; then exit 9; fi
[[ "$profile_loaded" == 1 && "$profile_status" == remove_failed ]]
''')

    def test_real_prepare_rejects_unprotected_or_injected_paths(self):
        for value in ('/tmp/fixture', '/var/lib/provenance-measurement-ci.*', '/var/lib/provenance-measurement-ci.ABC12345/evil'):
            result = subprocess.run(['bash', '-c', f'set -eu; source "{HELPER}"; fixture=$1 task_uid=61001 task_gid=61001; profile_prepare', 'test', value], capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_actual_permission_validator_before_exclusive_create(self):
        code = HELPER.read_text().split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        root = '/var/lib/provenance-measurement-ci.AbCd1234'
        class CreateReached(Exception):
            pass
        for bad in ('none', 'owner', 'mode', 'group', 'symlink', 'links', 'member', 'primary', 'ancestor', 'elf'):
            def info(path):
                binary = str(path).endswith('gvisor-smoke.test')
                own = str(path) == root or binary
                mode = (stat.S_IFREG | 0o550) if binary else stat.S_IFDIR | (0o710 if own else 0o755)
                return types.SimpleNamespace(st_mode=(stat.S_IFLNK | 0o777 if binary and bad == 'symlink' else mode | (0o002 if own and bad == 'mode' or not own and bad == 'ancestor' else 0)), st_uid=(1 if own and bad == 'owner' else 0), st_gid=(999 if own and bad == 'group' else 61001 if own else 0), st_nlink=(2 if binary and bad == 'links' else 1))
            with self.subTest(bad=bad), patch('sys.argv', ['test', root, '61001', '61001']), patch('grp.getgrgid', return_value=types.SimpleNamespace(gr_mem=['other'] if bad == 'member' else [])), patch('pwd.getpwall', return_value=[types.SimpleNamespace(pw_gid=61001, pw_uid=61001 if bad != 'primary' else 61002)]), patch.object(pathlib.Path, 'lstat', info), patch.object(pathlib.Path, 'open', return_value=io.BytesIO(b'nope' if bad == 'elf' else b'\x7fELF')), patch('os.open', side_effect=CreateReached) as opened:
                with self.assertRaises(CreateReached if bad == 'none' else AssertionError):
                    exec(code, {})
                if bad == 'none':
                    self.assertEqual(opened.call_args.args[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW)
                    self.assertEqual(opened.call_args.args[2], 0o400)
                else:
                    opened.assert_not_called()

    def test_fixture_wiring_preserves_guards_and_order(self):
        source = HELPER.with_name('test-measured-runtime-systemd.sh').read_text()
        self.assertLess(source.index('chmod 0710 "$fixture"'), source.index('profile_prepare'))
        self.assertIn('install -o 0 -g "$task_gid" -m 0550', source)
        self.assertLess(source.index('profile_remove || clean=0'), source.index('userdel "$task_user"'))
        self.assertIn('"$profile_loaded" == 0 && "$profile_uncertain" == 0', source)
        helper = HELPER.read_text()
        self.assertNotIn('--replace', helper)
        self.assertNotIn('--write-cache', helper)
        self.assertIn('grp.getgrgid(gid).gr_mem == []', helper)


if __name__ == '__main__':
    unittest.main()
