package gvisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const teardownPollInterval = 25 * time.Millisecond

// confirmContainerTeardown waits until the runtime state and systemd scope for
// exactly containerID are absent. It never removes runtime state files: doing
// so could conceal a live sandbox. Only after their absence is proven may it
// rmdir exact empty native cgroup leaves left by a partially started runtime.
func (p *Provider) confirmContainerTeardown(ctx context.Context, containerID string) error {
	if !validContainerID(containerID) {
		return errors.New("invalid container ID for teardown confirmation")
	}
	for {
		residue, err := p.containerTeardownResidue(containerID)
		if err != nil {
			return err
		}
		if len(residue) == 0 {
			return p.pruneEmptyNativeCgroups(containerID)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("container %s residue remains (%s): %w", containerID, strings.Join(residue, ", "), ctx.Err())
		case <-time.After(teardownPollInterval):
		}
	}
}

func (p *Provider) containerTeardownResidue(containerID string) ([]string, error) {
	entries, err := os.ReadDir(p.config.StateRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect gVisor state root: %w", err)
	}
	var residue []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), containerID) {
			residue = append(residue, filepath.Join(p.config.StateRoot, entry.Name()))
		}
	}
	if p.config.CgroupDriver == CgroupDriverSystemdUser {
		scope := systemdCgroupPath(p.config.SystemdCgroupRoot, containerID)
		if _, err := os.Lstat(scope); err == nil {
			residue = append(residue, scope)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect gVisor systemd scope: %w", err)
		}
	}
	sort.Strings(residue)
	return residue, nil
}
