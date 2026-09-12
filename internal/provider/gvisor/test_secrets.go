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

func addSecretMounts(spec *ociSpec, files *testsecrets.Files, bundle string) error {
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
	// gVisor's gofer prepares bind destinations before guest tmpfs mounts
	// exist. A guest tmpfs parent would therefore try to create children on
	// the immutable image. Supply an owned metadata-only skeleton instead:
	// every placeholder is empty; values remain exclusively in sealed memfds.
	root := filepath.Join(bundle, "test-secret-mountpoints")
	if err := os.Mkdir(root, 0755); err != nil {
		return errors.New("create test-secret mountpoints failed")
	}
	directory := filepath.Join(root, "provenance", "test-secrets")
	if err := os.MkdirAll(directory, 0755); err != nil {
		return errors.New("create test-secret mountpoints failed")
	}
	for _, mount := range mounts {
		placeholder, err := os.OpenFile(filepath.Join(directory, filepath.Base(mount.Destination)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0444)
		if err != nil {
			return errors.New("create test-secret mountpoints failed")
		}
		if err := placeholder.Close(); err != nil {
			return errors.New("create test-secret mountpoints failed")
		}
	}
	spec.Mounts = append(spec.Mounts, ociMount{Destination: "/run", Type: "bind", Source: root, Options: []string{"bind", "ro", "nosuid", "nodev", "noexec"}})
	for _, mount := range mounts {
		spec.Mounts = append(spec.Mounts, ociMount{Destination: mount.Destination, Type: "bind", Source: mount.Source, Options: []string{"bind", "ro", "nosuid", "nodev", "noexec"}})
	}
	return nil
}
