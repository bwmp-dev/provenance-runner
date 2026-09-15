//go:build linux

package testsecrets

import (
	"fmt"
	"os"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Descriptor is a caller-owned, read-only view of one sealed anonymous file.
// It is trusted composition input, never a job-selectable pathname. Every view
// must remain owned until its consumers have retired and must then be closed.
// Closing Files does not revoke an already transferred view.
type Descriptor struct {
	Name string   `json:"-"`
	File *os.File `json:"-"`
}

func (Descriptor) String() string   { return "[test-secret descriptor]" }
func (Descriptor) GoString() string { return "[test-secret descriptor]" }

const requiredSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

// ReadSealedDescriptor reads a received read-only descriptor only after checking
// its anonymous memory-file profile and immutable seals. It does not authenticate
// a sender, name, selection, lease or expiry: the root composition must do that
// before calling it. The caller owns successful bytes and must clear them after
// bounded tmpfs materialization. The caller also retains ownership of file.
func ReadSealedDescriptor(file *os.File) ([]byte, error) {
	before, err := sealedDescriptorStat(file, true)
	if err != nil {
		return nil, ErrUnavailable
	}
	value := make([]byte, int(before.Size))
	n, err := file.ReadAt(value, 0)
	after, checkErr := sealedDescriptorStat(file, true)
	if err != nil || n != len(value) || checkErr != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || !utf8.Valid(value) {
		clear(value)
		return nil, ErrUnavailable
	}
	return value, nil
}

// ReadOnlyDescriptors creates independent O_RDONLY descriptions, suitable for
// a descriptor-only channel that refuses writable descriptors. The deliberate
// procfs reopen refers only to an inode retained under this owner's lock; it
// does not accept a path from the job or weaken the channel's access checks.
func (f *Files) ReadOnlyDescriptors() ([]Descriptor, error) {
	if f == nil {
		return nil, ErrUnavailable
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || len(f.files) < 1 || len(f.files) > MaximumFiles {
		return nil, ErrUnavailable
	}
	var result []Descriptor
	success := false
	defer func() {
		if !success {
			for _, d := range result {
				_ = d.File.Close()
			}
		}
	}()
	total := int64(0)
	previous := ""
	for _, entry := range f.files {
		if len(entry.name) > 63 || !safeName.MatchString(entry.name) || entry.name <= previous {
			return nil, ErrUnavailable
		}
		previous = entry.name
		before, err := sealedDescriptorStat(entry.file, false)
		if err != nil {
			return nil, ErrUnavailable
		}
		total += before.Size
		if total > MaximumBytes {
			return nil, ErrUnavailable
		}
		fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", entry.file.Fd()), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, ErrUnavailable
		}
		view := os.NewFile(uintptr(fd), "test-secret-read-only")
		result = append(result, Descriptor{Name: entry.name, File: view})
		after, err := sealedDescriptorStat(view, true)
		if err != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mode != after.Mode {
			return nil, ErrUnavailable
		}
	}
	success = true
	return result, nil
}

func sealedDescriptorStat(file *os.File, readOnly bool) (unix.Stat_t, error) {
	var st unix.Stat_t
	if file == nil {
		return st, ErrUnavailable
	}
	fd := int(file.Fd())
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0444 || st.Nlink != 0 || st.Size < 1 || st.Size > MaximumBytes || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return st, ErrUnavailable
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals != requiredSeals {
		return st, ErrUnavailable
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || (readOnly && flags&unix.O_ACCMODE != unix.O_RDONLY) {
		return st, ErrUnavailable
	}
	fdFlags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
		return st, ErrUnavailable
	}
	return st, nil
}
