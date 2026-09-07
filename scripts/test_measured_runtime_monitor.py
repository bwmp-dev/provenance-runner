import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("monitor", Path(__file__).with_name("measured-runtime-monitor.py"))
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


class MonitorTests(unittest.TestCase):
    def test_scope_is_not_prefix_authority(self):
        root = "/user.slice/user-60001.slice/user@60001.service/app.slice"
        self.assertTrue(monitor.scope_matches("0::" + root + "/job.scope", root))
        for value in [root, root + "-other/job.scope", root + "/job.service", "/other/job.scope"]:
            self.assertFalse(monitor.scope_matches("0::" + value, root))

    def test_actual_executable_object_hash_and_role(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            process = root / "123"
            process.mkdir()
            exe = root / "frontend"
            exe.write_bytes(b"fixture executable bytes")
            (process / "exe").symlink_to(exe)
            (process / "stat").write_text("123 (fixture) " + " ".join(["0"] * 19 + ["41"]))
            (process / "cgroup").write_text("0::/fixture/job.scope\n")
            s = exe.stat()
            expected = (s.st_dev, s.st_ino, s.st_size, hashlib.sha256(exe.read_bytes()).hexdigest())
            for role in (b"runsc-sandbox", b"runsc-gofer"):
                (process / "cmdline").write_bytes(role + b"\0never-retain-this-argument")
                record = monitor.inspect(123, os.getuid(), "/fixture", expected, root)
                self.assertEqual(record["role"], role.decode())
                self.assertNotIn("never-retain", str(record))
            self.assertIsNone(monitor.inspect(123, os.getuid() + 1, "/fixture", expected, root))
            with self.assertRaises(ValueError):
                monitor.inspect(123, os.getuid(), "/fixture", (*expected[:3], "0" * 64), root)
            other = root / "same-bytes-different-object"
            other.write_bytes(exe.read_bytes())
            (process / "exe").unlink()
            (process / "exe").symlink_to(other)
            with self.assertRaises(ValueError):
                monitor.inspect(123, os.getuid(), "/fixture", expected, root)

    def test_fixture_guard_fails_before_any_privilege_operation(self):
        script = Path(__file__).with_name("test-measured-runtime-systemd.sh")
        result = subprocess.run(["bash", str(script)], env={"PATH": os.environ["PATH"]}, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_cleanup_does_not_remove_existing_user_data_or_shared_device(self):
        script = Path(__file__).with_name("test-measured-runtime-systemd.sh").read_text()
        self.assertNotIn("userdel -r", script)
        self.assertNotIn("chmod", "\n".join(line for line in script.splitlines() if '"$loop"' in line))
        self.assertIn('[[ "$user_created" == 1 ]]', script)
        self.assertIn('[[ "$root_mounted" == 1 ]]', script)
        self.assertIn('[[ "$clean" == 1 && "$fixture" =~', script)
        self.assertLess(script.index("trap cleanup EXIT"), script.index('chmod 0711 "$fixture"'))
        self.assertIn('getent group "$task_gid"', script)
        self.assertIn('for attempt in {1..50}', script)

    def test_evidence_failures_propagate_from_cleanup(self):
        script = Path(__file__).with_name("test-measured-runtime-systemd.sh").read_text()
        function = script[script.index("cleanup() {"):script.index("trap cleanup EXIT")]
        # Exercise actual cleanup function with no resource ownership and
        # isolated output, replacing only external recording utilities.
        for failing in ("jq", "sha256sum", "chown"):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as tmp:
                shell = ('set -u\n' + function + '\n'
                         'fixture=$1 evidence=$1 task_user=fixture task_uid= task_gid= loop= image=\n'
                         'monitor_pid= manager_started=0 root_mounted=0 user_created=0 evidence_created=1 cleanup_error=0\n'
                         'jq() { echo "{}"; }; sha256sum() { return 0; }; chown() { return 0; };\n'
                         + failing + '() { return 1; };\ntrue\ncleanup\n')
                result = subprocess.run(["bash", "-c", shell, "cleanup-test", tmp], capture_output=True)
                self.assertEqual(result.returncode, 1, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
