//go:build linux

package networkpolicy

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
)

// ControllerResources retains the dedicated journal parent, whose provisioned
// ceiling covers one workload and one router at their maximum leaf limits.
// It never configures a host cgroup or adopts a pathname supplied by a job.
type ControllerResources struct {
	mu              sync.Mutex
	journal         *JobCgroupJournal
	parent          *os.File
	dev, ino        uint64
	controls        [8]string
	invalid, closed bool
}

var controllerResourceControls = [8]string{"cpu.max", "cpu.max.burst", "memory.max", "memory.swap.max", "pids.max", "cgroup.max.descendants", "cgroup.max.depth", "memory.oom.group"}

func controllerResourceValues(maximum *p.ResourceLimits) ([8]string, error) {
	if maximum == nil || len(maximum.ProtoReflect().GetUnknown()) != 0 || maximum.CpuMillis < 10 || maximum.CpuMillis > 64000 || maximum.MemoryBytes < 16<<20 || maximum.MemoryBytes > 64<<30 || maximum.ProcessCount == 0 || maximum.ProcessCount > 4096 || maximum.DiskBytes < 1<<20 || maximum.DiskBytes > 64<<30 {
		return [8]string{}, ErrResources
	}
	return [8]string{strconv.FormatUint(2*uint64(maximum.CpuMillis)*100, 10) + " 100000\n", "0\n", strconv.FormatUint(2*maximum.MemoryBytes, 10) + "\n", "0\n", strconv.FormatUint(2*(uint64(maximum.ProcessCount)+MappedRuntimeProcessReserve), 10) + "\n", "2\n", "1\n", "1\n"}, nil
}

func RetainControllerResources(journal *JobCgroupJournal, maximum *p.ResourceLimits) (*ControllerResources, error) {
	values, err := controllerResourceValues(maximum)
	if err != nil || journal == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrResources
	}
	journal.mu.Lock()
	if journal.closed || journal.controllerResources != nil || len(journal.active) != 0 || !protectedCgroup(journal.parent, true) {
		journal.mu.Unlock()
		return nil, ErrResources
	}
	fd, err := unix.FcntlInt(journal.parent.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		journal.mu.Unlock()
		return nil, ErrResources
	}
	r := &ControllerResources{journal: journal, parent: os.NewFile(uintptr(fd), "controller-resource-parent"), dev: journal.parentDev, ino: journal.parentIno, controls: values}
	journal.controllerResources = r
	journal.mu.Unlock()
	if r.Validate() != nil {
		if err := r.Close(); err != nil {
			return r, errors.Join(ErrResources, err)
		}
		return nil, ErrResources
	}
	return r, nil
}

func (r *ControllerResources) Validate() (result error) {
	if r == nil {
		return ErrResources
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer func() {
		if result != nil {
			r.invalid = true
		}
	}()
	if r.closed || r.invalid || r.journal == nil || !protectedCgroup(r.parent, true) {
		return ErrResources
	}
	r.journal.mu.Lock()
	owned := !r.journal.closed && r.journal.controllerResources == r && r.journal.parentDev == r.dev && r.journal.parentIno == r.ino
	r.journal.mu.Unlock()
	var st unix.Stat_t
	if !owned || unix.Fstat(int(r.parent.Fd()), &st) != nil || uint64(st.Dev) != r.dev || st.Ino != r.ino {
		return ErrResources
	}
	root, err := os.Open("/sys/fs/cgroup")
	if err != nil {
		return ErrResources
	}
	var rootStat unix.Stat_t
	err = unix.Fstat(int(root.Fd()), &rootStat)
	closeErr := root.Close()
	if err != nil || closeErr != nil || (rootStat.Dev == st.Dev && rootStat.Ino == st.Ino) {
		return ErrResources
	}
	for i, name := range controllerResourceControls {
		if raw, err := readCgroupControl(r.parent, name); err != nil || raw != r.controls[i] {
			return ErrResources
		}
	}
	for _, name := range []string{"cgroup.procs", "cgroup.threads"} {
		if raw, err := readCgroupControl(r.parent, name); err != nil || raw != "" {
			return ErrResources
		}
	}
	if raw, err := readCgroupControl(r.parent, "cgroup.type"); err != nil || raw != "domain\n" {
		return ErrResources
	}
	raw, err := readCgroupControl(r.parent, "cgroup.subtree_control")
	if err != nil {
		return ErrResources
	}
	controls := " " + strings.Join(strings.Fields(raw), " ") + " "
	for _, name := range []string{"cpu", "memory", "pids"} {
		if !strings.Contains(controls, " "+name+" ") {
			return ErrResources
		}
	}
	return nil
}

func (r *ControllerResources) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if r.journal == nil || r.parent == nil {
		return ErrResources
	}
	r.journal.mu.Lock()
	defer r.journal.mu.Unlock()
	if len(r.journal.active) != 0 || r.journal.controllerResources != r {
		return ErrResources
	}
	if err := r.parent.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	r.closed = true
	r.journal.controllerResources = nil
	return nil
}
