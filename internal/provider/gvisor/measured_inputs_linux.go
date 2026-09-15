//go:build linux

package gvisor

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"regexp"

	"golang.org/x/sys/unix"
)

var errMeasuredInputs = errors.New("measured_input_staging_unavailable")
var measuredInputName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type measuredInput struct {
	Name   string
	Source *os.File
	Size   uint64
	SHA256 [32]byte
}

func localInputFilesystem(file *os.File) bool {
	if file == nil {
		return false
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &fs) != nil {
		return false
	}
	return fs.Type == unix.EXT4_SUPER_MAGIC || fs.Type == unix.XFS_SUPER_MAGIC || fs.Type == unix.BTRFS_SUPER_MAGIC || fs.Type == unix.TMPFS_MAGIC
}

// stageMeasuredInputs copies a bounded flat inventory into a newly created,
// empty root-private directory. Sources are regular read-only file descriptors,
// never paths, archives, sockets or FIFOs. The caller retains descriptor ownership
// until return and must separately own/journal the bundle and launch lifecycle.
// Success seals the directory for guest reads; it grants no launch authority.
func stageMeasuredInputs(ctx context.Context, directory *os.File, inputs []measuredInput, maximum uint64) (result error) {
	var parent unix.Stat_t
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || directory == nil || maximum == 0 || maximum > 64<<30 || len(inputs) > 256 || !localInputFilesystem(directory) || unix.Fstat(int(directory.Fd()), &parent) != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Mode&07777 != 0700 || parent.Uid != 0 || parent.Gid != 0 {
		return errMeasuredInputs
	}
	fd, err := unix.Openat2(int(directory.Fd()), ".", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return errMeasuredInputs
	}
	owned := os.NewFile(uintptr(fd), "private-input-directory")
	defer func() {
		if owned.Close() != nil {
			result = errors.Join(result, errMeasuredInputs)
		}
	}()
	entries, err := owned.ReadDir(1)
	if err != io.EOF || len(entries) != 0 {
		return errMeasuredInputs
	}
	seen := make(map[string]bool, len(inputs))
	total := uint64(0)
	for _, input := range inputs {
		if !measuredInputName.MatchString(input.Name) || seen[input.Name] || input.Source == nil || input.SHA256 == ([32]byte{}) || input.Size > maximum-total {
			return errMeasuredInputs
		}
		total += input.Size
		seen[input.Name] = true
	}
	type createdInput struct {
		name string
		file *os.File
	}
	var created []createdInput
	defer func() {
		if result != nil {
			// Only names created by this invocation, still bound to their exact
			// retained inodes, can be removed. Never sweep/adopt other contents.
			_ = owned.Chmod(0700)
			for _, entry := range created {
				var actual, retained unix.Stat_t
				if unix.Fstat(int(entry.file.Fd()), &retained) != nil || unix.Fstatat(fd, entry.name, &actual, unix.AT_SYMLINK_NOFOLLOW) != nil || actual.Dev != retained.Dev || actual.Ino != retained.Ino || unix.Unlinkat(fd, entry.name, 0) != nil {
					result = errors.Join(result, errMeasuredInputs)
				}
			}
			if owned.Sync() != nil {
				result = errors.Join(result, errMeasuredInputs)
			}
		}
		for _, entry := range created {
			if entry.file.Close() != nil {
				result = errors.Join(result, errMeasuredInputs)
			}
		}
	}()
	for _, input := range inputs {
		if ctx.Err() != nil {
			return errMeasuredInputs
		}
		flags, err := unix.FcntlInt(input.Source.Fd(), unix.F_GETFL, 0)
		var before unix.Stat_t
		if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 || !localInputFilesystem(input.Source) || unix.Fstat(int(input.Source.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || uint64(before.Size) != input.Size {
			return errMeasuredInputs
		}
		outFD, err := unix.Openat2(fd, input.Name, &unix.OpenHow{Flags: unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW, Mode: 0600, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return errMeasuredInputs
		}
		output := os.NewFile(uintptr(outFD), "staged-input")
		created = append(created, createdInput{input.Name, output})
		hash := sha256.New()
		reader := io.NewSectionReader(input.Source, 0, int64(input.Size)+1)
		var buffer [32768]byte
		copied := uint64(0)
		for {
			if ctx.Err() != nil {
				return errMeasuredInputs
			}
			n, readErr := reader.Read(buffer[:])
			if copied+uint64(n) > input.Size {
				return errMeasuredInputs
			}
			if n != 0 {
				if written, err := output.Write(buffer[:n]); err != nil || written != n {
					return errMeasuredInputs
				}
				_, _ = hash.Write(buffer[:n])
				copied += uint64(n)
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil || n == 0 {
				return errMeasuredInputs
			}
		}
		var after unix.Stat_t
		if copied != input.Size || [32]byte(hash.Sum(nil)) != input.SHA256 || unix.Fstat(int(input.Source.Fd()), &after) != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size || after.Mtim != before.Mtim || after.Ctim != before.Ctim || output.Chmod(0444) != nil || output.Sync() != nil {
			return errMeasuredInputs
		}
	}
	if ctx.Err() != nil || owned.Chmod(0555) != nil || owned.Sync() != nil {
		return errMeasuredInputs
	}
	return nil
}
