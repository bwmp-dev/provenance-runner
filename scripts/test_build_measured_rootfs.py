import argparse
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("build-measured-rootfs.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ImageBuilderTests(unittest.TestCase):
    def archive(self, path, entries):
        with tarfile.open(path, "w") as archive:
            for name, kind, value in entries:
                member = tarfile.TarInfo(name)
                member.uid, member.gid = os.getuid(), os.getgid()
                member.mode = 0o755 if kind == "directory" else 0o644
                if kind == "directory":
                    member.type = tarfile.DIRTYPE
                elif kind == "symlink":
                    member.type, member.linkname = tarfile.SYMTYPE, value
                elif kind == "device":
                    member.type = tarfile.CHRTYPE
                else:
                    member.size = len(value)
                archive.addfile(member, io.BytesIO(value) if kind == "file" else None)

    def test_unsafe_archives(self):
        cases = [
            [("../escape", "file", b"x")],
            [("dev/device", "device", b"")],
            [("escape", "symlink", "../outside")],
            [("link", "symlink", "/bin"), ("link/write", "file", b"x")],
            [("same", "file", b"x"), ("same", "file", b"y")],
            [("tmp/leftover", "file", b"x")],
            [("a", "symlink", "b"), ("b", "symlink", "a")],
            [("dir", "directory", b""), ("dir/root", "symlink", ".."), ("escape", "symlink", "dir/root/../outside")],
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                self.archive(path / "source.tar", entries)
                (path / "tree").mkdir()
                with open(path / "source.tar", "rb") as source, self.assertRaises(builder.Invalid):
                    builder.extract(source, path / "tree", os.getuid(), os.getgid())

    def test_real_reproducible_builder_and_exclusive_output(self):
        executable = shutil.which("mksquashfs")
        self.assertIsNotNone(executable, "actual mksquashfs is required for builder acceptance")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            self.archive(path / "source.tar", [("bin", "directory", b""), ("bin/tool", "file", b"fixture")])
            args = argparse.Namespace(source=str(path / "source.tar"),
                source_sha256=hashlib.sha256((path / "source.tar").read_bytes()).hexdigest(),
                builder=executable, builder_sha256=hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
                output=str(path / "output"), uid=os.getuid(), gid=os.getgid())
            result = builder.build(args)
            self.assertEqual(2, result["reproducibleBuilds"])
            image = path / "output" / ("sha256-" + result["sha256"] + ".squashfs")
            self.assertEqual(result["sha256"], hashlib.sha256(image.read_bytes()).hexdigest())
            self.assertEqual(0o400, image.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                builder.build(args)
            args.source_sha256 = "0" * 64
            with self.assertRaises(builder.Invalid):
                builder.build(args)


if __name__ == "__main__":
    unittest.main()
