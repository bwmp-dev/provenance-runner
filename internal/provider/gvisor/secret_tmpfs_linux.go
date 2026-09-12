//go:build linux

package gvisor

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The private parent is never mounted into a guest. Only a single job's run
// subtree is exposed, read-only. Paths contain ownership identity, never values.
func (p *Provider) secretTmpfsRoot() string {
	digest := sha256.Sum256([]byte(p.config.StateRoot))
	return filepath.Join("/dev/shm", fmt.Sprintf("provenance-secrets-%d-%x", os.Getuid(), digest[:16]))
}

func validateSecretTmpfsRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	uid, gid, ownershipErr := rootFSOwnership(root)
	currentUID, currentGID := rootFSCurrentIdentity()
	var fs unix.Statfs_t
	if !info.IsDir() || info.Mode().Perm() != 0700 || ownershipErr != nil || uid != currentUID || gid != currentGID || unix.Statfs(root, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return errors.New("test-secret private tmpfs unavailable")
	}
	return nil
}

func (p *Provider) createSecretTmpfs(containerID string) (string, error) {
	if !validContainerID(containerID) {
		return "", errors.New("invalid test-secret container identity")
	}
	root := p.secretTmpfsRoot()
	if err := os.Mkdir(root, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", errors.New("create test-secret private tmpfs failed")
	}
	if err := validateSecretTmpfsRoot(root); err != nil {
		return "", errors.New("test-secret private tmpfs unavailable")
	}
	job := filepath.Join(root, containerID)
	if err := os.Mkdir(job, 0700); err != nil {
		return "", errors.New("create test-secret private job directory failed")
	}
	return filepath.Join(job, "run"), nil
}

func (p *Provider) removeSecretTmpfs(containerID string) error {
	if !validContainerID(containerID) {
		return errors.New("invalid test-secret container identity")
	}
	root := p.secretTmpfsRoot()
	if err := validateSecretTmpfsRoot(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("test-secret cleanup root unavailable")
	}
	// Exact, derived job identity only; never traverse a caller-supplied path.
	if err := os.RemoveAll(filepath.Join(root, containerID)); err != nil {
		return errors.New("test-secret tmpfs cleanup failed")
	}
	return nil
}
