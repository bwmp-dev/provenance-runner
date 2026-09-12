package gvisor

import (
	"errors"
	"strconv"
	"strings"

	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
)

const secretMountReserve = int64(1 << 20)

func validateSecretRoot(root string, files *testsecrets.Files) error {
	if _, err := files.Mounts(); err != nil {
		return errors.New("test-secret memory handles unavailable")
	}
	// Only /run is an image mountpoint. All dynamic child names are created in
	// the overlaid private tmpfs, never by editing the immutable host image.
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

func addSecretMounts(spec *ociSpec, files *testsecrets.Files) error {
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
	spec.Mounts = append(spec.Mounts, ociMount{Destination: "/run", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "noexec", "mode=0555", "size=" + strconv.FormatInt(secretMountReserve, 10)}})
	for _, mount := range mounts {
		spec.Mounts = append(spec.Mounts, ociMount{Destination: mount.Destination, Type: "bind", Source: mount.Source, Options: []string{"bind", "ro", "nosuid", "nodev", "noexec"}})
	}
	return nil
}
