//go:build linux

// Package testsecrets owns anonymous, sealed memory files for one job. It does
// not authenticate deliveries or advertise protocol support by itself.
package testsecrets

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const MaximumBytes = 65536
const MaximumFiles = 64
const Destination = "/run/provenance/test-secrets"

var ErrUnavailable = errors.New("test-secret memory files unavailable")
var safeName = regexp.MustCompile(`^[a-z][a-z0-9]*([._-][a-z0-9]+)*$`)

// Input is ephemeral trusted-composition input, never job/environment JSON.
// The caller owns Value and must clear it after preparing files and redaction.
type Input struct {
	Name  string `json:"-"`
	Value []byte `json:"-"`
}

func (Input) String() string   { return "[test-secret input]" }
func (Input) GoString() string { return "[test-secret input]" }

type memoryFile struct {
	name string
	file *os.File
}
type Files struct {
	mu     sync.Mutex
	files  []memoryFile
	closed bool
}

func (*Files) String() string   { return "[test-secret memory files]" }
func (*Files) GoString() string { return "[test-secret memory files]" }

// New validates the entire name-ordered set before allocating any file. Each
// inode is anonymous shmem, sealed against all writes, growth and truncation.
// Nothing is created beneath the workspace or a host-visible shared directory.
// This is not a guarantee against swap, a debugger or forensic memory recovery.
func New(inputs []Input) (*Files, error) {
	if len(inputs) < 1 || len(inputs) > MaximumFiles {
		return nil, ErrUnavailable
	}
	total := 0
	previous := ""
	for _, input := range inputs {
		if len(input.Name) > 63 || !safeName.MatchString(input.Name) || input.Name <= previous || len(input.Value) == 0 || len(input.Value) > MaximumBytes || !utf8.Valid(input.Value) {
			return nil, ErrUnavailable
		}
		previous = input.Name
		total += len(input.Value)
		if total > MaximumBytes {
			return nil, ErrUnavailable
		}
	}
	result := &Files{}
	for _, input := range inputs {
		f, err := sealed(input.Value)
		if err != nil {
			_ = result.Close()
			return nil, ErrUnavailable
		}
		result.files = append(result.files, memoryFile{input.Name, f})
	}
	return result, nil
}

func sealed(value []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate("provenance-test-secret", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "test-secret-memory")
	success := false
	defer func() {
		if !success {
			_ = f.Close()
		}
	}()
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return nil, ErrUnavailable
	}
	if n, err := f.Write(value); err != nil || n != len(value) {
		return nil, ErrUnavailable
	}
	// The guest UID differs from the host runner UID. Read permission on this
	// unnamed inode does not publish a host pathname: opening its /proc handle
	// still requires permission to inspect the trusted runner process. The OCI
	// mount must additionally be read-only, nosuid, nodev and noexec.
	if f.Chmod(0444) != nil {
		return nil, ErrUnavailable
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return nil, ErrUnavailable
	}
	if actual, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0); err != nil || actual != seals {
		return nil, ErrUnavailable
	}
	if _, err = f.Seek(0, 0); err != nil {
		return nil, ErrUnavailable
	}
	success = true
	return f, nil
}

// Mount describes only a retained anonymous descriptor, never value bytes. It
// must not be accepted from customer JSON or used after Files.Close. The owning
// process must retain Files until sandbox/gofer teardown has completed.
type Mount struct {
	Source      string
	Destination string
}

func (f *Files) Mounts() ([]Mount, error) {
	if f == nil {
		return nil, ErrUnavailable
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, ErrUnavailable
	}
	mounts := make([]Mount, 0, len(f.files))
	for _, file := range f.files {
		mounts = append(mounts, Mount{fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.file.Fd()), Destination + "/" + file.name})
	}
	return mounts, nil
}

// Close releases the owner's descriptors. The sandbox and every process with
// a retained descriptor must already be destroyed; closing alone cannot revoke
// another holder's reference. Startup reconciliation must kill orphaned jobs
// before capacity is reused. Close is idempotent and never removes host paths.
func (f *Files) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	var result error
	for _, file := range f.files {
		if file.file.Close() != nil {
			result = ErrUnavailable
		}
	}
	f.files = nil
	return result
}
