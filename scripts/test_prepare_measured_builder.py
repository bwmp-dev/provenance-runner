import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

script = Path(__file__).with_name("prepare-measured-builder.sh")
namespace = {"__name__": "builder_test"}
exec(script.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0], namespace)


class ProvisionTests(unittest.TestCase):
    def test_existing_and_symlink_destination_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                namespace["ancestry"](root, False)
            (root / "link").symlink_to(root / "missing")
            with self.assertRaises(ValueError):
                namespace["ancestry"](root / "link", False)
            namespace["ancestry"](root / "fresh", False)
            with self.assertRaises(ValueError):
                namespace["ancestry"](root / "fresh", True)

    def test_named_regular_file_identity_and_no_overwrite(self):
        data = b"\x7fELFfixture"
        def archive(kind=tarfile.REGTYPE, duplicate=False):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w") as tar:
                for _ in range(2 if duplicate else 1):
                    member = tarfile.TarInfo("./usr/bin/tool")
                    member.type = kind
                    member.size = len(data) if kind == tarfile.REGTYPE else 0
                    member.linkname = "/outside"
                    tar.addfile(member, io.BytesIO(data))
            return output.getvalue()
        wanted = [("./usr/bin/tool", "mksquashfs", hashlib.sha256(data).hexdigest())]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for payload in (archive(tarfile.SYMTYPE), archive(duplicate=True)):
                with mock.patch.object(namespace["subprocess"], "run", return_value=subprocess.CompletedProcess([], 0, payload)):
                    with self.assertRaises(ValueError):
                        namespace["unpack"](Path("fixture.deb"), wanted, root)
            with mock.patch.object(namespace["subprocess"], "run", return_value=subprocess.CompletedProcess([], 0, archive())):
                with self.assertRaises(ValueError):
                    namespace["unpack"](Path("fixture.deb"), [(wanted[0][0], "mksquashfs", "0" * 64)], root)
                namespace["unpack"](Path("fixture.deb"), wanted, root)
                self.assertEqual((root / "mksquashfs").read_bytes(), data)
                with self.assertRaises(FileExistsError):
                    namespace["unpack"](Path("fixture.deb"), wanted, root)

    def test_default_requires_privilege_and_canonical_destination(self):
        with mock.patch.object(namespace["os"], "geteuid", return_value=1000), mock.patch.object(namespace["sys"], "argv", ["script", "/new"]):
            with self.assertRaises(ValueError):
                namespace["main"]()
        with self.assertRaises(ValueError):
            namespace["ancestry"](Path("relative"), False)

    def test_pins_and_download_bounds_are_not_optional(self):
        text = script.read_text()
        self.assertIn('"--max-time", "45"', text)
        self.assertIn('"--max-filesize", "16777216"', text)
        self.assertIn('"--proto", "=https"', text)
        self.assertIn('"hermeticToolchain": False', text)
        self.assertEqual(len(namespace["PACKAGES"]), 6)
        self.assertEqual(namespace["PACKAGES"][0][2][0][2], "47d5c1af3da11864e64c9dc6bb4e568719dcc315e6a744e79381ce3374fb7393")

    def test_download_corruption_fails_before_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "fresh"
            def download(command, **kwargs):
                self.assertEqual(command[0], "curl")
                Path(command[command.index("--output") + 1]).write_bytes(b"corrupt package")
                return subprocess.CompletedProcess(command, 0)
            with mock.patch.object(namespace["sys"], "argv", ["script", "--verify-downloads", str(destination)]), mock.patch.object(namespace["subprocess"], "run", side_effect=download) as runner:
                with self.assertRaisesRegex(ValueError, "package identity mismatch"):
                    namespace["main"]()
                self.assertEqual(runner.call_count, 1)
                self.assertFalse((destination / "mksquashfs").exists())


if __name__ == "__main__":
    unittest.main()
