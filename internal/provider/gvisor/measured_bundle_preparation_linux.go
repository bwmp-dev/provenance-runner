//go:build linux

package gvisor

import (
	"context"
	"encoding/json"
	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	"io"
	"os"
	"path/filepath"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type preparedBundleEntry struct {
	name string
	stat unix.Stat_t
}

const measuredResolverConfiguration = "nameserver 10.0.1.1\noptions timeout:1 attempts:1\n"

type measuredBundlePreparation struct {
	mapping     np.MappedIdentity
	entries     []preparedBundleEntry
	directories []preparedBundleEntry
}

func validPreparationMapping(m np.MappedIdentity) bool {
	for _, id := range []uint32{m.UID, m.GID, m.OverflowUID, m.OverflowGID} {
		if id == 0 || id == ^uint32(0) {
			return false
		}
	}
	return m.UID != m.OverflowUID && m.GID != m.OverflowGID
}

// prepare is a trusted-controller operation, never a worker-selected host path
// or UID endpoint. Provisioning supplies the exclusive mapping and staging
// ceiling. Command/environment values must be non-secret configuration; secret
// materialization is a separate ephemeral channel, not persistent OCI JSON.
func (b *measuredBundle) prepare(ctx context.Context, job *p.JobSpecification, command measuredGuestCommand, privateRoot string, mapping np.MappedIdentity, inputs []measuredInput, maximum uint64) error {
	if b == nil || b.owner == nil || ctx == nil || ctx.Err() != nil || job == nil || os.Getuid() != 0 || os.Geteuid() != 0 || !validPreparationMapping(mapping) || maximum == 0 || maximum > 64<<30 {
		return errMeasuredBundle
	}
	job = proto.Clone(job).(*p.JobSpecification)
	spec, err := buildMeasuredNetworkSpec(job, command, privateRoot)
	if err != nil {
		return errMeasuredBundle
	}
	j := b.owner
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.checkLocked(b, job) != nil || b.prepared != nil || b.preparationFailed || !b.matchesPrivateRoot(privateRoot) || !persistentBundleFile(b.directory, true, 0700) {
		return errMeasuredBundle
	}
	view, err := openBundleAt(b.directory, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return errMeasuredBundle
	}
	entries, readErr := view.ReadDir(1)
	closeErr := view.Close()
	if readErr != io.EOF || len(entries) != 0 || closeErr != nil {
		return errMeasuredBundle
	}
	// A partial preparation can only be cleaned up, not retried or launched.
	// Invalid input does not poison unrelated jobs' durable ownership journal.
	b.preparationFailed = true
	if b.record.SecretBoot != "" {
		if reserveMeasuredSecretStorage(&spec) != nil {
			return errMeasuredBundle
		}
		if !j.secretPathValid() || j.checkSecretDirectory(b.record) != nil {
			return errMeasuredBundle
		}
		dir, err := openBundleAt(j.secretParent, b.record.Job, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			return errMeasuredBundle
		}
		if unix.Mkdirat(int(dir.Fd()), "files", 0700) != nil {
			dir.Close()
			return errMeasuredBundle
		}
		inner, err := openBundleAt(dir, "files", unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			dir.Close()
			return errMeasuredBundle
		}
		innerOwnerErr, innerModeErr := inner.Chown(0, int(mapping.GID)), inner.Chmod(0555)
		innerCloseErr := inner.Close()
		ownerErr, modeErr := dir.Chown(0, int(mapping.GID)), dir.Chmod(0550)
		closeErr := dir.Close()
		if ownerErr != nil || modeErr != nil || closeErr != nil || innerOwnerErr != nil || innerModeErr != nil || innerCloseErr != nil {
			return errMeasuredBundle
		}
		// Only the inner directory is visible to the guest. The outer 0550
		// directory restricts host access to root and the mapped gofer group;
		// inner 0555 permits the guest's different, non-root virtual identity.
		spec.Mounts = append(spec.Mounts, ociMount{Destination: ts.Destination, Type: "bind", Source: filepath.Join(j.secretPath, b.record.Job, "files"), Options: []string{"bind", "ro", "nosuid", "nodev", "noexec"}})
	}
	raw, err := json.Marshal(spec)
	if err != nil || len(raw) > 1<<20 {
		return errMeasuredBundle
	}
	for _, name := range []string{".measured-root", ".runsc-state", "inputs"} {
		if unix.Mkdirat(int(b.directory.Fd()), name, 0700) != nil {
			return errMeasuredBundle
		}
	}
	inputDir, err := openBundleAt(b.directory, "inputs", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return errMeasuredBundle
	}
	err = stageMeasuredInputs(ctx, inputDir, inputs, maximum)
	closeErr = inputDir.Close()
	if err != nil || closeErr != nil {
		return errMeasuredBundle
	}
	for _, entry := range []struct {
		name     string
		contents []byte
	}{{"config.json", raw}, {"resolv.conf", []byte(measuredResolverConfiguration)}} {
		config, err := openBundleAt(b.directory, entry.name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
		if err != nil {
			return errMeasuredBundle
		}
		n, writeErr := config.Write(entry.contents)
		modeErr := config.Chmod(0444)
		syncErr := config.Sync()
		closeErr = config.Close()
		if n != len(entry.contents) || writeErr != nil || modeErr != nil || syncErr != nil || closeErr != nil {
			return errMeasuredBundle
		}
	}
	proof := &measuredBundlePreparation{mapping: mapping}
	names := []string{"config.json", "resolv.conf", "inputs"}
	for _, input := range inputs {
		names = append(names, filepath.Join("inputs", input.Name))
	}
	for _, name := range names {
		f, err := openBundleAt(b.directory, name, unix.O_PATH, 0)
		if err != nil {
			return errMeasuredBundle
		}
		var st unix.Stat_t
		err = unix.Fstat(int(f.Fd()), &st)
		closeErr = f.Close()
		mode := uint32(unix.S_IFREG | 0444)
		if name == "inputs" {
			mode = unix.S_IFDIR | 0555
		}
		if err != nil || closeErr != nil || st.Uid != 0 || st.Gid != 0 || st.Mode != mode || st.Nlink == 0 || (name != "inputs" && st.Nlink != 1) {
			return errMeasuredBundle
		}
		proof.entries = append(proof.entries, preparedBundleEntry{name, st})
	}
	for _, name := range []string{".measured-root", ".runsc-state"} {
		f, err := openBundleAt(b.directory, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			return errMeasuredBundle
		}
		err = f.Chown(int(mapping.UID), int(mapping.GID))
		var st unix.Stat_t
		statErr := unix.Fstat(int(f.Fd()), &st)
		syncErr := f.Sync()
		closeErr = f.Close()
		if err != nil || statErr != nil || syncErr != nil || closeErr != nil {
			return errMeasuredBundle
		}
		proof.directories = append(proof.directories, preparedBundleEntry{name, st})
	}
	if ctx.Err() != nil || b.directory.Chown(int(mapping.UID), int(mapping.GID)) != nil || b.directory.Sync() != nil {
		return errMeasuredBundle
	}
	b.prepared = proof
	b.preparationFailed = false
	return nil
}

// Every content inode was privately created and verified before sealing. Root
// ownership, readonly mode, single-link identity and unchanged metadata prove
// the mapped runtime cannot replace or modify those inputs/configuration. No
// caller-owned source descriptor remains in the guest mount inventory.
func (b *measuredBundle) checkPrepared(mapping np.MappedIdentity) (result error) {
	if b == nil || b.owner == nil {
		return errMeasuredBundle
	}
	j := b.owner
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || !j.ready || b.retired || b.preparationFailed || b.prepared == nil || j.active[b.record.Job] != b {
		return errMeasuredBundle
	}
	defer func() {
		if result != nil {
			b.preparationFailed = true
		}
	}()
	if b.prepared.mapping != mapping {
		return errMeasuredBundle
	}
	if j.checkSecretDirectory(b.record) != nil {
		return errMeasuredBundle
	}
	var root unix.Stat_t
	if unix.Fstat(int(b.directory.Fd()), &root) != nil || root.Uid != mapping.UID || root.Gid != mapping.GID || root.Mode != unix.S_IFDIR|0700 {
		return errMeasuredBundle
	}
	for _, entry := range b.prepared.entries {
		f, err := openBundleAt(b.directory, entry.name, unix.O_PATH, 0)
		if err != nil {
			return errMeasuredBundle
		}
		var st unix.Stat_t
		err = unix.Fstat(int(f.Fd()), &st)
		closeErr := f.Close()
		want := entry.stat
		if err != nil || closeErr != nil || st.Dev != want.Dev || st.Ino != want.Ino || st.Uid != want.Uid || st.Gid != want.Gid || st.Mode != want.Mode || st.Nlink != want.Nlink || st.Size != want.Size || st.Mtim != want.Mtim || st.Ctim != want.Ctim {
			return errMeasuredBundle
		}
	}
	for _, entry := range b.prepared.directories {
		f, err := openBundleAt(b.directory, entry.name, unix.O_PATH|unix.O_DIRECTORY, 0)
		if err != nil {
			return errMeasuredBundle
		}
		var st unix.Stat_t
		err = unix.Fstat(int(f.Fd()), &st)
		closeErr := f.Close()
		if err != nil || closeErr != nil || st.Dev != entry.stat.Dev || st.Ino != entry.stat.Ino || st.Uid != mapping.UID || st.Gid != mapping.GID || st.Mode != unix.S_IFDIR|0700 {
			return errMeasuredBundle
		}
	}
	return nil
}
