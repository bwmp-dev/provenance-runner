//go:build linux

package runtimeidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/buildinfo"
	"golang.org/x/sys/unix"
)

const maximumExecutableBytes = int64(512 << 20)
const maximumImageBytes = int64(4 << 30)

// Lease retains the actual objects until execution and cleanup have finished.
// Paths reference this living process's retained descriptors, never re-open the
// configured executable/root pathname. No descriptor is passed into the guest.
type Lease struct {
	runner, sandbox, root, image, loop *os.File
	runnerHash, sandboxHash, imageHash string
	imageStat                          unix.Stat_t
	mountID                            uint64
	mapping                            unix.LoopInfo64
	snapshot                           Snapshot
	closed                             bool
}

func reference(file *os.File) string { return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd()) }
func (l *Lease) RunnerPath() string  { return reference(l.runner) }
func (l *Lease) SandboxPath() string { return reference(l.sandbox) }
func (l *Lease) RootPath() string    { return reference(l.root) }
func (l *Lease) ImagePath() string   { return reference(l.image) }
func (l *Lease) LoopPath() string    { return reference(l.loop) }
func (l *Lease) Snapshot() Snapshot  { return l.snapshot }
func (l *Lease) Close() error {
	if l == nil || l.closed {
		return nil
	}
	l.closed = true
	var result error
	for _, f := range []*os.File{l.loop, l.image, l.root, l.sandbox, l.runner} {
		if f != nil {
			if err := f.Close(); err != nil {
				result = ErrUnavailable
			}
		}
	}
	return result
}

// Acquire never converts or mounts anything. A configured measured path either
// establishes every identity, or returns a safe error to abort that execution.
func Acquire(ctx context.Context, sandboxPath, rootPath, imagePath string, loopPaths ...string) (result *Lease, err error) {
	if len(loopPaths) > 1 {
		return nil, ErrUnavailable
	}
	l := &Lease{}
	defer func() {
		if err != nil {
			l.Close()
		}
	}()
	l.runner, err = os.Open("/proc/self/exe")
	if err != nil {
		return nil, ErrUnavailable
	}
	l.runnerHash, err = hashObject(l.runner, maximumExecutableBytes, true)
	if err != nil {
		return nil, err
	}
	l.sandbox, err = openProtected(sandboxPath, false)
	if err != nil {
		return nil, err
	}
	l.sandboxHash, err = hashObject(l.sandbox, maximumExecutableBytes, true)
	if err != nil {
		return nil, err
	}
	l.image, err = openProtected(imagePath, false)
	if err != nil {
		return nil, err
	}
	l.imageHash, err = hashObject(l.image, maximumImageBytes, false)
	if err != nil {
		return nil, err
	}
	if unix.Fstat(int(l.image.Fd()), &l.imageStat) != nil {
		return nil, ErrUnavailable
	}
	l.root, err = openProtectedRoot(rootPath)
	if err != nil {
		return nil, err
	}
	mount, err := inspectMount(l.root)
	if err != nil {
		return nil, err
	}
	l.mountID = mount.id
	loopPath := fmt.Sprintf("/dev/loop%d", mount.minor)
	if len(loopPaths) == 1 && loopPaths[0] != "" {
		loopPath = loopPaths[0]
	}
	l.loop, err = openProtectedLoop(loopPath)
	if err != nil {
		return nil, ErrUnavailable
	}
	var device unix.Stat_t
	if unix.Fstat(int(l.loop.Fd()), &device) != nil || device.Mode&unix.S_IFMT != unix.S_IFBLK || unix.Major(device.Rdev) != 7 || unix.Minor(device.Rdev) != mount.minor {
		return nil, ErrDrift
	}
	mapping, err := unix.IoctlLoopGetStatus64(int(l.loop.Fd()))
	if err != nil {
		return nil, ErrUnavailable
	}
	l.mapping = *mapping
	if !l.validMapping(mapping) {
		return nil, ErrDrift
	}
	version, err := sandboxVersion(ctx, l.SandboxPath())
	if err != nil {
		return nil, err
	}
	l.snapshot = Snapshot{RunnerVersion: buildinfo.Version, RunnerExecutableSHA256: l.runnerHash, SandboxKind: "gvisor", SandboxVersion: version, SandboxExecutableSHA256: l.sandboxHash, NetworkMode: "none", RootFS: RootFS{Format: "squashfs-image-sha256/v1", SHA256: l.imageHash}}
	if !l.snapshot.Valid() {
		return nil, ErrUnavailable
	}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Lease) validMapping(m *unix.LoopInfo64) bool {
	return m.Device == uint64(l.imageStat.Dev) && m.Inode == l.imageStat.Ino && m.Offset == 0 && m.Sizelimit == 0 && m.Encrypt_type == 0 && m.Encrypt_key_size == 0 && m.Flags&unix.LO_FLAGS_READ_ONLY != 0
}

func (l *Lease) Validate() error {
	if l == nil || l.closed {
		return ErrUnavailable
	}
	mount, err := inspectMount(l.root)
	if err != nil || mount.id != l.mountID {
		return ErrDrift
	}
	m, err := unix.IoctlLoopGetStatus64(int(l.loop.Fd()))
	if err != nil || !l.validMapping(m) || *m != l.mapping {
		return ErrDrift
	}
	for _, item := range []struct {
		file  *os.File
		limit int64
		elf   bool
		hash  string
	}{{l.runner, maximumExecutableBytes, true, l.runnerHash}, {l.sandbox, maximumExecutableBytes, true, l.sandboxHash}, {l.image, maximumImageBytes, false, l.imageHash}} {
		if item.file != l.runner {
			var s unix.Stat_t
			if unix.Fstat(int(item.file.Fd()), &s) != nil || s.Uid != 0 || s.Mode&06022 != 0 || s.Nlink != 1 {
				return ErrDrift
			}
		}
		hash, err := hashObject(item.file, item.limit, item.elf)
		if err != nil || hash != item.hash {
			return ErrDrift
		}
	}
	return nil
}

func openProtected(path string, directory bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnavailable
	}
	// Check every parent. Root-owned sticky directories protect root-owned
	// publication entries; ordinary writable directories are not acceptable.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		var s unix.Stat_t
		if unix.Lstat(parent, &s) != nil || s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Uid != 0 || (s.Mode&0022 != 0 && s.Mode&unix.S_ISVTX == 0) {
			return nil, ErrUnavailable
		}
		if parent == "/" {
			break
		}
	}
	flags := uint64(unix.O_RDONLY | unix.O_CLOEXEC)
	if directory {
		flags = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: flags, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "runtime-object")
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || s.Uid != 0 || s.Mode&06022 != 0 || (!directory && (s.Mode&unix.S_IFMT != unix.S_IFREG || s.Nlink != 1)) {
		f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}

func openProtectedRoot(path string) (*os.File, error) {
	// The mounted root's embedded UID is the runner's, per the existing layout
	// contract. Its publication parent, unlike the immutable inode, is root-owned.
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnavailable
	}
	parent, err := openProtected(filepath.Dir(path), true)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat2(int(parent.Fd()), filepath.Base(path), &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), "runtime-root"), nil
}

func openProtectedLoop(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnavailable
	}
	parent, err := openProtected(filepath.Dir(path), true)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat2(int(parent.Fd()), filepath.Base(path), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), "runtime-loop")
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFBLK || info.Uid != 0 || info.Mode&0022 != 0 || info.Nlink != 1 {
		file.Close()
		return nil, ErrUnavailable
	}
	return file, nil
}

func hashObject(f *os.File, maximum int64, elf bool) (string, error) {
	var before, after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size <= 0 || before.Size > maximum {
		return "", ErrUnavailable
	}
	if elf {
		var magic [4]byte
		if _, err := f.ReadAt(magic[:], 0); err != nil || !bytes.Equal(magic[:], []byte{0x7f, 'E', 'L', 'F'}) {
			return "", ErrUnavailable
		}
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.NewSectionReader(f, 0, before.Size))
	if err != nil || n != before.Size || unix.Fstat(int(f.Fd()), &after) != nil {
		return "", ErrUnavailable
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return "", ErrDrift
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type mountIdentity struct {
	id    uint64
	minor uint32
}

func inspectMount(root *os.File) (mountIdentity, error) {
	var fs unix.Statfs_t
	var sx unix.Statx_t
	if unix.Fstatfs(int(root.Fd()), &fs) != nil || fs.Type != unix.SQUASHFS_MAGIC || fs.Flags&unix.ST_RDONLY == 0 || unix.Statx(int(root.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &sx) != nil || sx.Mask&unix.STATX_MNT_ID == 0 {
		return mountIdentity{}, ErrUnavailable
	}
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return mountIdentity{}, ErrUnavailable
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return mountIdentity{}, ErrUnavailable
	}
	var target string
	var found bool
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id != sx.Mnt_id {
			continue
		}
		split := strings.Split(line, " - ")
		if len(split) != 2 || !strings.HasPrefix(split[1], "squashfs ") || fields[3] != "/" || !strings.Contains(","+fields[5]+",", ",ro,") || fields[2] != fmt.Sprintf("7:%d", sx.Dev_minor) {
			return mountIdentity{}, ErrDrift
		}
		target = fields[4]
		found = true
	}
	if !found {
		return mountIdentity{}, ErrDrift
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && strings.HasPrefix(fields[4], target+"/") {
			return mountIdentity{}, ErrDrift
		}
	}
	return mountIdentity{sx.Mnt_id, sx.Dev_minor}, nil
}

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 4096 - b.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.overflow = true
	}
	b.Buffer.Write(p)
	return n, nil
}
func sandboxVersion(parent context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	var output boundedOutput
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if cmd.Run() != nil || output.overflow {
		return "", ErrUnavailable
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) < 1 || len(lines) > 4 || !strings.HasPrefix(lines[0], "runsc version ") {
		return "", ErrUnavailable
	}
	version := strings.TrimPrefix(lines[0], "runsc version ")
	if !versionPattern.MatchString(version) {
		return "", ErrUnavailable
	}
	return version, nil
}
