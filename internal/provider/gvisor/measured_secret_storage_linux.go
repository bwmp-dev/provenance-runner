//go:build linux

package gvisor

import (
	"context"
	"io"
	"os"
	"regexp"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	"golang.org/x/sys/unix"
)

var measuredSecretName = regexp.MustCompile(`^[a-z][a-z0-9]*([._-][a-z0-9]+)*$`)

// stageMeasuredSecrets is a private, one-shot materializer, not admission or a
// pathname endpoint. Its caller must already own a durably recorded, exclusive
// tmpfs directory and authenticate the complete selection and delivery expiry.
// Partial failure leaves that directory with its cleanup owner; it never falls
// back to persistent storage or removes a live consumer's files. Descriptors
// remain borrowed. No value or value hash is persisted in the journal or OCI.
func stageMeasuredSecrets(ctx context.Context, directory *os.File, descriptors []ts.Descriptor, mapping np.MappedIdentity, expires time.Time) error {
	if ctx == nil || ctx.Err() != nil || directory == nil || os.Getuid() != 0 || os.Geteuid() != 0 || !validPreparationMapping(mapping) || len(descriptors) < 1 || len(descriptors) > ts.MaximumFiles || !expires.After(time.Now()) {
		return errMeasuredBundle
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(int(directory.Fd()), &st) != nil || st.Uid != 0 || st.Nlink == 0 || unix.Fstatfs(int(directory.Fd()), &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return errMeasuredBundle
	}
	if !((st.Mode == unix.S_IFDIR|0700 && st.Gid == 0) || (st.Mode == unix.S_IFDIR|0550 && st.Gid == mapping.GID)) {
		return errMeasuredBundle
	}
	view, err := openBundleAt(directory, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return errMeasuredBundle
	}
	entries, readErr := view.ReadDir(1)
	closeErr := view.Close()
	if len(entries) != 0 || readErr != io.EOF || closeErr != nil {
		return errMeasuredBundle
	}
	// Validate and bound the entire set before creating the first file. Retained
	// byte buffers are at most 64 KiB and are cleared on every return path.
	values := make([][]byte, 0, len(descriptors))
	defer func() {
		for _, value := range values {
			clear(value)
		}
	}()
	total := 0
	previous := ""
	for _, d := range descriptors {
		if ctx.Err() != nil || !expires.After(time.Now()) || len(d.Name) > 63 || !measuredSecretName.MatchString(d.Name) || d.Name <= previous {
			return errMeasuredBundle
		}
		previous = d.Name
		// Check the remaining budget before allocating the next value. The
		// sealed reader independently verifies identity, seals and exact size.
		if d.File == nil {
			return errMeasuredBundle
		}
		info, statErr := d.File.Stat()
		if statErr != nil || info.Size() < 1 || info.Size() > int64(ts.MaximumBytes-total) {
			return errMeasuredBundle
		}
		value, err := ts.ReadSealedDescriptor(d.File)
		if err != nil {
			return errMeasuredBundle
		}
		values = append(values, value)
		total += len(value)
		if total > ts.MaximumBytes {
			return errMeasuredBundle
		}
	}
	for i, d := range descriptors {
		if ctx.Err() != nil || !expires.After(time.Now()) {
			return errMeasuredBundle
		}
		file, err := openBundleAt(directory, d.Name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
		if err != nil {
			return errMeasuredBundle
		}
		n, writeErr := file.Write(values[i])
		modeErr := file.Chmod(0444)
		closeErr := file.Close()
		if writeErr != nil || n != len(values[i]) || modeErr != nil || closeErr != nil {
			return errMeasuredBundle
		}
		clear(values[i])
	}
	// The mapped gofer can read/traverse, but cannot create or replace entries.
	// The future OCI mount must independently enforce ro,nosuid,nodev,noexec.
	if ctx.Err() != nil || !expires.After(time.Now()) || directory.Chown(0, int(mapping.GID)) != nil || directory.Chmod(0550) != nil {
		return errMeasuredBundle
	}
	return nil
}
