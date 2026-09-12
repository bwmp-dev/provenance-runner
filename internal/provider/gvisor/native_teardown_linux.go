package gvisor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// runsc can fail before persisting its cgroup handle. A subsequent successful
// delete then leaves an empty cgroup. Remove only exact candidate leaf paths;
// the kernel refuses rmdir for populated groups or groups with children. Never
// recursively remove cgroup state, kill an inferred PID, or mask an error.
func (p *Provider) pruneEmptyNativeCgroups(containerID string) error {
	if p.config.CgroupDriver != CgroupDriverRunsc {
		return nil
	}
	if !validContainerID(containerID) {
		return errors.New("invalid native cgroup identity")
	}
	for _, path := range cgroupUsageRootsForEnvironment(containerID, "") {
		if !strings.HasPrefix(path, "/sys/fs/cgroup/") || filepath.Base(path) != containerID {
			return errors.New("invalid native cgroup cleanup path")
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() {
			return errors.New("native cgroup cleanup target unavailable")
		}
		var fs unix.Statfs_t
		if unix.Statfs(path, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
			return errors.New("native cgroup cleanup target is not cgroup v2")
		}
		if err := unix.Rmdir(path); err != nil && !errors.Is(err, unix.ENOENT) {
			return errors.New("native cgroup remains after runtime deletion")
		}
	}
	return nil
}
