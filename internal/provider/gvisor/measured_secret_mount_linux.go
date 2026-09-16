//go:build linux

package gvisor

import (
	"context"
	"strconv"
	"strings"
	"time"

	ts "github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
)

// Keep the private bounded secret subtree within the job's existing disk
// ceiling, including a fixed metadata reserve, rather than adding storage.
func reserveMeasuredSecretStorage(spec *ociSpec) error {
	if spec == nil {
		return errMeasuredBundle
	}
	for i := range spec.Mounts {
		mount := &spec.Mounts[i]
		if mount.Destination != "/tmp" || mount.Type != "tmpfs" {
			continue
		}
		for k, option := range mount.Options {
			if !strings.HasPrefix(option, "size=") {
				continue
			}
			size, err := strconv.ParseInt(strings.TrimPrefix(option, "size="), 10, 64)
			if err != nil || size <= secretMountReserve {
				return errMeasuredBundle
			}
			mount.Options[k] = "size=" + strconv.FormatInt(size-secretMountReserve, 10)
			return nil
		}
	}
	return errMeasuredBundle
}

// Private late materialization hook. The service must separately authenticate
// selection, lease, expiry and peer before invoking it; this is not a wire API.
// Failure consumes the one-shot attempt and leaves cleanup ownership intact.
func (b *measuredBundle) stageSecrets(ctx context.Context, job *p.JobSpecification, descriptors []ts.Descriptor, expires time.Time) error {
	if b == nil || b.owner == nil || ctx == nil || ctx.Err() != nil {
		return errMeasuredBundle
	}
	j := b.owner
	j.mu.Lock()
	defer j.mu.Unlock()
	if b.record.SecretBoot == "" || b.prepared == nil || b.preparationFailed || b.secretAttempted || j.checkLocked(b, job) != nil {
		return errMeasuredBundle
	}
	b.secretAttempted = true
	dir, err := openBundleAt(j.secretParent, b.record.Job, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return errMeasuredBundle
	}
	defer dir.Close()
	if stageMeasuredSecrets(ctx, dir, descriptors, b.prepared.mapping, expires) != nil || j.checkSecretDirectory(b.record) != nil {
		return errMeasuredBundle
	}
	return nil
}
