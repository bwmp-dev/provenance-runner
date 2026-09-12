package gvisor

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
)

const secretMountReserve = int64(1 << 20)

func validateSecretRoot(root string, files *testsecrets.Files) error {
	if _, err := files.Mounts(); err != nil {
		return errors.New("test-secret memory handles unavailable")
	}
	// Only /run is an image mountpoint. Dynamic child names live in a private
	// metadata-only bind mount, never in the immutable host image.
	path, err := validateRootFSMountTarget(root, "/run", rootFSMountTarget{destination: "/run", kind: rootFSMountDirectory, mode: 0755})
	if err != nil {
		return errors.New("test-secret root mountpoint unavailable")
	}
	uid, gid, err := rootFSOwnership(path)
	currentUID, currentGID := rootFSCurrentIdentity()
	if err != nil || uid != currentUID || gid != currentGID || requireReadOnlyFilesystem(path) != nil {
		return errors.New("test-secret root mountpoint is not immutable")
	}
	return nil
}

func (p *Provider) addSecretMounts(spec *ociSpec, files *testsecrets.Files, containerID string) error {
	if files == nil {
		return nil
	}
	mounts, err := files.Mounts()
	if err != nil || len(mounts) == 0 {
		return errors.New("test-secret memory handles unavailable")
	}
	// Reserve within the existing job disk budget instead of adding an
	// unaccounted writable filesystem. The guest cannot write the /run root.
	reserved := false
	for i := range spec.Mounts {
		if spec.Mounts[i].Destination != "/tmp" {
			continue
		}
		for j, option := range spec.Mounts[i].Options {
			if !strings.HasPrefix(option, "size=") {
				continue
			}
			size, err := strconv.ParseInt(strings.TrimPrefix(option, "size="), 10, 64)
			if err != nil || size <= secretMountReserve {
				return errors.New("test-secret tmpfs budget unavailable")
			}
			spec.Mounts[i].Options[j] = "size=" + strconv.FormatInt(size-secretMountReserve, 10)
			reserved = true
		}
	}
	if !reserved {
		return errors.New("test-secret tmpfs budget unavailable")
	}
	// memfd inodes cannot be directly bind-mounted by this runtime. Copy into
	// a verified private tmpfs, then expose only the job subtree read-only.
	// No value is ever written to the bundle or immutable image.
	root, err := p.createSecretTmpfs(containerID)
	if err != nil {
		return err
	}
	directory := filepath.Join(root, "provenance", "test-secrets")
	if err := os.MkdirAll(directory, 0755); err != nil {
		return errors.New("create test-secret mountpoints failed")
	}
	for _, path := range []string{root, filepath.Dir(directory), directory} {
		if err := os.Chmod(path, 0755); err != nil {
			return errors.New("prepare new test-secret guest directory failed")
		}
	}
	values, err := files.RedactionValues()
	if err != nil || len(values) != len(mounts) {
		return errors.New("test-secret memory handles unavailable")
	}
	for i, mount := range mounts {
		file, err := os.OpenFile(filepath.Join(directory, filepath.Base(mount.Destination)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
		if err != nil {
			return errors.New("create private tmpfs test-secret failed")
		}
		_, writeErr := file.WriteString(values[i])
		modeErr := file.Chmod(0444)
		closeErr := file.Close()
		values[i] = ""
		if writeErr != nil || modeErr != nil || closeErr != nil {
			return errors.New("prepare private tmpfs test-secret failed")
		}
	}
	spec.Mounts = append(spec.Mounts, ociMount{Destination: "/run", Type: "bind", Source: root, Options: []string{"bind", "ro", "nosuid", "nodev", "noexec"}})
	return nil
}
