import argparse
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("build-measured-rootfs.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ImageBuilderTests(unittest.TestCase):
    def test_closed_secret_mountpoint(self):
        for case in ('valid', 'symlink-parent', 'symlink-target', 'file-parent', 'nonempty', 'writable'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'root'
                root.mkdir()
                outside = Path(directory) / 'outside'
                outside.mkdir()
                if case == 'symlink-parent':
                    (root / 'run').symlink_to(outside, target_is_directory=True)
                elif case == 'file-parent':
                    (root / 'run').write_bytes(b'preserve')
                elif case in ('symlink-target', 'nonempty', 'writable'):
                    (root / 'run/provenance').mkdir(parents=True, mode=0o755)
                    target = root / 'run/provenance/test-secrets'
                    if case == 'symlink-target':
                        target.symlink_to(outside, target_is_directory=True)
                    else:
                        target.mkdir(mode=0o755)
                        if case == 'nonempty':
                            (target / 'preserve').write_bytes(b'preserve')
                        else:
                            target.chmod(0o777)
                if case == 'valid':
                    builder.install_secret_mountpoint(root, os.getuid(), os.getgid())
                    target = root / 'run/provenance/test-secrets'
                    self.assertEqual(0o755, target.stat().st_mode & 0o7777)
                    self.assertEqual([], list(target.iterdir()))
                else:
                    with self.assertRaises(builder.Invalid):
                        builder.install_secret_mountpoint(root, os.getuid(), os.getgid())
                self.assertEqual([], list(outside.iterdir()))

    def paper_guest(self):
        # ELF-shaped inert bytes: the builder never executes this input.
        value = bytearray(120)
        value[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", value, 16, 2, 62)
        struct.pack_into("<Q", value, 32, 64)
        struct.pack_into("<HH", value, 54, 56, 1)
        struct.pack_into("<I", value, 64, 1)
        return bytes(value)

    def test_pinned_paper_guest_copy_and_refusals(self):
        for case in ("valid", "hash", "dynamic", "existing"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                root = path / "tree"
                root.mkdir()
                value = bytearray(self.paper_guest())
                if case == "dynamic":
                    struct.pack_into("<I", value, 64, 3)
                (path / "helper").write_bytes(value)
                expected = hashlib.sha256(value).hexdigest()
                if case == "hash":
                    expected = "0" * 64
                if case == "existing":
                    (root / "provenance-measured-paper").write_bytes(b"preserve")
                with open(path / "helper", "rb") as helper:
                    if case == "valid":
                        builder.install_paper_guest(helper, expected, root, os.getuid(), os.getgid())
                        target = root / "provenance-measured-paper"
                        self.assertEqual(bytes(value), target.read_bytes())
                        self.assertEqual(0o555, target.stat().st_mode & 0o777)
                        self.assertEqual([], list((root / 'run/provenance/test-secrets').iterdir()))
                    else:
                        with self.assertRaises((builder.Invalid, FileExistsError)):
                            builder.install_paper_guest(helper, expected, root, os.getuid(), os.getgid())
                        if case == "existing":
                            self.assertEqual(b"preserve", (root / "provenance-measured-paper").read_bytes())

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
            [("etc", "symlink", "bin"), ("bin", "directory", b"")],
            [("etc", "directory", b""), ("etc/resolv.conf", "symlink", "other"), ("etc/other", "file", b"x")],
            [("etc", "directory", b""), ("etc/resolv.conf", "directory", b"")],
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

    def test_regular_resolver_mount_target(self):
        for entries in ([], [("etc", "directory", b""), ("etc/resolv.conf", "file", b"source-metadata")]):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                self.archive(path / "source.tar", entries)
                (path / "tree").mkdir()
                with open(path / "source.tar", "rb") as source:
                    builder.extract(source, path / "tree", os.getuid(), os.getgid())
                resolver = path / "tree/etc/resolv.conf"
                self.assertTrue(resolver.is_file())
                self.assertFalse(resolver.is_symlink())
                self.assertEqual(b"source-metadata" if entries else b"", resolver.read_bytes())
                if not entries:
                    self.assertEqual(0o444, resolver.stat().st_mode & 0o777)

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

    def test_real_builder_includes_pinned_paper_guest(self):
        executable = shutil.which("mksquashfs")
        self.assertIsNotNone(executable)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            self.archive(path / "source.tar", [])
            (path / "helper").write_bytes(self.paper_guest())
            args = argparse.Namespace(source=str(path / "source.tar"),
                source_sha256=hashlib.sha256((path / "source.tar").read_bytes()).hexdigest(),
                builder=executable, builder_sha256=hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
                output=str(path / "output"), uid=os.getuid(), gid=os.getgid(),
                paper_guest=str(path / "helper"), paper_guest_sha256=hashlib.sha256(self.paper_guest()).hexdigest())
            result = builder.build(args)
            self.assertEqual(args.paper_guest_sha256, result["paperGuestSha256"])
            self.assertEqual(2, result["reproducibleBuilds"])


if __name__ == "__main__":
    unittest.main()
