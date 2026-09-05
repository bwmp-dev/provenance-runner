package gvisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

type rootFSMountTargetKind uint8

const (
	rootFSMountDirectory rootFSMountTargetKind = iota + 1
	rootFSMountRegularFile
	rootFSSpecialPermissions = os.ModeSticky | os.ModeSetuid | os.ModeSetgid
)

type rootFSMountTarget struct {
	destination string
	kind        rootFSMountTargetKind
	mode        os.FileMode
	empty       bool
}

var fixedRootFSMountTargets = []rootFSMountTarget{
	{destination: "/proc", kind: rootFSMountDirectory, mode: 0o700},
	{destination: "/dev", kind: rootFSMountDirectory, mode: 0o700},
	{destination: "/dev/pts", kind: rootFSMountDirectory, mode: 0o700},
	// runsc resolves the configured working directory before installing its
	// mounts. The sandbox identity therefore needs traversal permission on the
	// otherwise empty, read-only host mount target.
	{destination: "/workspace", kind: rootFSMountDirectory, mode: 0o711},
	{destination: "/tmp", kind: rootFSMountDirectory, mode: os.ModeSticky | 0o700},
	{destination: "/inputs", kind: rootFSMountDirectory, mode: 0o700},
	{destination: "/runtime", kind: rootFSMountDirectory, mode: 0o700},
	{destination: "/tmp/provenance-probe-events.ndjson", kind: rootFSMountRegularFile, mode: 0o600, empty: true},
}

type rootFSReadOnlyCheck func(string) error

func validateImmutableRootFS(rootFS string, mounts []execution.ReadOnlyMount, eventFile *execution.StructuredEventFile) error {
	return validateRootFS(rootFS, mounts, eventFile, requireReadOnlyFilesystem)
}

func validateRootFS(rootFS string, mounts []execution.ReadOnlyMount, eventFile *execution.StructuredEventFile, readOnly rootFSReadOnlyCheck) error {
	if readOnly == nil {
		return errors.New("root filesystem read-only check is unavailable")
	}
	if err := readOnly(rootFS); err != nil {
		return fmt.Errorf("root filesystem must be mounted read-only: %w", err)
	}
	rootInfo, err := os.Lstat(rootFS)
	if err != nil {
		return fmt.Errorf("inspect root filesystem: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return errors.New("root filesystem must be a non-symbolic-link directory")
	}
	rootMode := rootInfo.Mode() & (os.ModePerm | rootFSSpecialPermissions)
	if rootMode != 0o700 {
		return fmt.Errorf("root filesystem mode is %s, want %s", rootMode, os.FileMode(0o700))
	}
	rootUID, rootGID, err := rootFSOwnership(rootFS)
	if err != nil {
		return fmt.Errorf("inspect root filesystem ownership: %w", err)
	}
	currentUID, currentGID := rootFSCurrentIdentity()
	if rootUID != currentUID || rootGID != currentGID {
		return fmt.Errorf("root filesystem owner is %d:%d, want runner identity %d:%d", rootUID, rootGID, currentUID, currentGID)
	}

	targets := append([]rootFSMountTarget(nil), fixedRootFSMountTargets...)
	for _, mount := range mounts {
		kind, err := rootFSMountSourceKind(mount.Source)
		if err != nil {
			return fmt.Errorf("inspect source for root filesystem mount target %q: %w", mount.Destination, err)
		}
		target := rootFSMountTarget{destination: mount.Destination, kind: kind}
		if kind == rootFSMountDirectory {
			target.mode = 0o700
		} else {
			target.mode = 0o600
			target.empty = true
		}
		targets = append(targets, target)
	}
	if eventFile != nil {
		targets = append(targets, rootFSMountTarget{destination: eventFile.Destination, kind: rootFSMountRegularFile, mode: 0o600, empty: true})
	}

	seen := make(map[string]rootFSMountTarget, len(targets))
	for _, target := range targets {
		clean := filepath.ToSlash(filepath.Clean(target.destination))
		if clean != target.destination || !strings.HasPrefix(clean, "/") || clean == "/" {
			return fmt.Errorf("root filesystem mount target %q must be a clean absolute container path", target.destination)
		}
		if previous, duplicate := seen[clean]; duplicate {
			if previous.kind != target.kind || previous.mode != target.mode || previous.empty != target.empty {
				return fmt.Errorf("root filesystem mount target %q has conflicting type or mode requirements", clean)
			}
			continue
		}
		seen[clean] = target
		hostPath, err := validateRootFSMountTarget(rootFS, clean, target)
		if err != nil {
			return err
		}
		uid, gid, err := rootFSOwnership(hostPath)
		if err != nil {
			return fmt.Errorf("inspect root filesystem mount target %q ownership: %w", clean, err)
		}
		if uid != rootUID || gid != rootGID {
			return fmt.Errorf("root filesystem mount target %q owner is %d:%d, want %d:%d", clean, uid, gid, rootUID, rootGID)
		}
		if err := readOnly(hostPath); err != nil {
			return fmt.Errorf("root filesystem mount target %q is not on a read-only mount: %w", clean, err)
		}
	}
	return nil
}

func rootFSMountSourceKind(source string) (rootFSMountTargetKind, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("mount source cannot be a symbolic link")
	}
	if info.IsDir() {
		return rootFSMountDirectory, nil
	}
	if info.Mode().IsRegular() {
		return rootFSMountRegularFile, nil
	}
	return 0, errors.New("mount source must be a regular file or directory")
}

func validateRootFSMountTarget(rootFS, destination string, target rootFSMountTarget) (string, error) {
	relative := strings.TrimPrefix(destination, "/")
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("root filesystem mount target %q escapes the root filesystem", destination)
	}
	components := strings.Split(filepath.FromSlash(relative), string(filepath.Separator))
	current := rootFS
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("root filesystem mount target %q escapes the root filesystem", destination)
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("root filesystem mount target %q is missing", destination)
			}
			return "", fmt.Errorf("inspect root filesystem mount target %q: %w", destination, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("root filesystem mount target %q contains symbolic link %q", destination, current)
		}
		last := index == len(components)-1
		if !last && !info.IsDir() {
			return "", fmt.Errorf("root filesystem mount target %q has non-directory ancestor %q", destination, current)
		}
		if !last {
			continue
		}
		switch target.kind {
		case rootFSMountDirectory:
			if !info.IsDir() {
				return "", fmt.Errorf("root filesystem mount target %q must be a directory", destination)
			}
		case rootFSMountRegularFile:
			if !info.Mode().IsRegular() {
				return "", fmt.Errorf("root filesystem mount target %q must be a regular file", destination)
			}
		default:
			return "", fmt.Errorf("root filesystem mount target %q has an unsupported type", destination)
		}
		if target.mode != 0 {
			actualMode := info.Mode() & (os.ModePerm | rootFSSpecialPermissions)
			if actualMode != target.mode {
				return "", fmt.Errorf("root filesystem mount target %q mode is %s, want %s", destination, actualMode, target.mode)
			}
		}
		if target.empty && info.Size() != 0 {
			return "", fmt.Errorf("root filesystem mount target %q must be empty", destination)
		}
	}
	return current, nil
}
