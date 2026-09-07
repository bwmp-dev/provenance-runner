import contextlib
import errno
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch, Mock

spec = importlib.util.spec_from_file_location("preflight",Path(__file__).with_name("measured-runtime-preflight.py"))
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class PreflightTests(unittest.TestCase):
    def test_safe_scalar_record_and_permission_probe(self):
        reads = {"/proc/sys/kernel/unprivileged_userns_clone":"0", "/proc/sys/user/max_user_namespaces":"12000", "/proc/sys/kernel/apparmor_restrict_unprivileged_userns":"1", "/proc/self/attr/current":"private marker", "/sys/module/apparmor/parameters/enabled":"Y"}
        libc = Mock()
        libc.unshare.return_value = -1
        output = io.StringIO()
        with patch.object(preflight.os,"getuid",return_value=61001), patch.object(Path,"read_text",lambda p:reads[str(p)]), patch.object(preflight.subprocess,"run",return_value=subprocess.CompletedProcess([],0,b"private marker",b"private marker")), patch.object(preflight.ctypes,"CDLL",return_value=libc), patch.object(preflight.ctypes,"get_errno",return_value=errno.EPERM), contextlib.redirect_stdout(output):
            preflight.main()
        record = json.loads(output.getvalue())
        self.assertEqual(record["namespaceProbe"],"permission")
        self.assertEqual(record["restrictNamespaces"],"unavailable")
        self.assertEqual(record["confinement"],"confined")
        self.assertEqual(record["maxUserNamespaces"],12000)
        self.assertNotIn("private marker",output.getvalue())

    def test_root_diagnostic_refused(self):
        with patch.object(preflight.os,"getuid",return_value=0), self.assertRaises(SystemExit):
            preflight.main()


if __name__ == "__main__":
    unittest.main()
