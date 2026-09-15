//go:build linux

package gvisor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

var ErrMeasuredNetworkLaunch = errors.New("measured_network_launch_unavailable")

// MeasuredNetworkLaunchConfig is trusted controller input, never a privileged
// RPC payload or workload-selected host path/command. OCI bundle construction,
// provisioning and crash recovery remain the controller's obligations.
type MeasuredNetworkLaunchConfig struct {
	Job                   *p.JobSpecification
	Measurement           *runtimeidentity.Lease
	Scope                 *np.JobCgroup
	Journal               *np.JobCgroupJournal
	Bundle                *measuredBundle
	Authority             *np.AuthorityRoute
	Mapping               np.MappedIdentity
	PrivateRoot           string
	Stdin, Stdout, Stderr *os.File
}

// MeasuredNetworkProcess owns a gated direct child and its whole job cgroup.
// Main-process exit alone is not cleanup. Wait and Close require whole-scope
// cleanup too; neither claims route, mount, workspace or reservation cleanup.
type MeasuredNetworkProcess struct {
	mu                                  sync.Mutex
	job                                 *p.JobSpecification
	measurement                         *runtimeidentity.Lease
	scope                               *np.JobCgroup
	journal                             *np.JobCgroupJournal
	bundle                              *measuredBundle
	privateRoot                         string
	mapping                             np.MappedIdentity
	authority                           *np.AuthorityRoute
	child                               *np.ChildNamespaces
	resources                           *np.RetainedResources
	link                                *np.PrivateJobLink
	gate                                *os.File
	cmd                                 *exec.Cmd
	done                                chan struct{}
	exitErr, closeErr                   error
	started, released, stopping, closed bool
}

// StartMeasuredNetworkProcess creates but does not release a measured child.
// A non-nil result owns Scope, including on failure: Close must succeed before
// the caller deletes its workspace. A nil result leaves Scope with the caller.
// Standard files need remain open only until this function returns; the child
// receives kernel duplicates, never generic unbounded I/O copier goroutines.
func StartMeasuredNetworkProcess(ctx context.Context, config MeasuredNetworkLaunchConfig) (*MeasuredNetworkProcess, error) {
	groups, err := os.Getgroups()
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || err != nil || len(groups) != 0 || config.Job == nil || config.Measurement == nil || config.Scope == nil || config.Journal == nil || config.Authority == nil || config.Stdin == nil || config.Stdout == nil || config.Stderr == nil {
		return nil, ErrMeasuredNetworkLaunch
	}
	job := proto.Clone(config.Job).(*p.JobSpecification)
	if config.Authority.CheckJob(job) != nil || config.Journal.CheckScope(config.Scope) != nil || config.Bundle == nil || config.Bundle.owner == nil || config.Bundle.scope != config.Scope || config.Bundle.owner.cgroups != config.Journal || config.Bundle.owner.check(config.Bundle, job) != nil || !config.Bundle.matchesPrivateRoot(config.PrivateRoot) || config.Bundle.checkPrepared(config.Mapping) != nil {
		return nil, ErrMeasuredNetworkLaunch
	}
	m := config.Mapping
	args := []string{job.GetLease().GetJobId(), strconv.FormatUint(uint64(m.UID), 10), strconv.FormatUint(uint64(m.GID), 10), strconv.FormatUint(uint64(m.OverflowUID), 10), strconv.FormatUint(uint64(m.OverflowGID), 10), config.PrivateRoot, config.Measurement.Snapshot().RootFS.SHA256, "embedded-executable"}
	if _, _, ok := measuredNetworkInputs(args); !ok {
		return nil, ErrMeasuredNetworkLaunch
	}
	measurement, err := config.Measurement.Retain()
	if err != nil {
		return nil, ErrMeasuredNetworkLaunch
	}
	s := &MeasuredNetworkProcess{job: job, measurement: measurement, scope: config.Scope, journal: config.Journal, bundle: config.Bundle, privateRoot: config.PrivateRoot, mapping: m, authority: config.Authority, done: make(chan struct{})}
	fail := func(err error) (*MeasuredNetworkProcess, error) {
		return s, errors.Join(ErrMeasuredNetworkLaunch, err, s.Close(context.Background()))
	}
	scope, err := s.scope.LaunchFD(job)
	if err != nil {
		return fail(err)
	}
	defer scope.Close()
	var files []*os.File
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	for i, path := range []string{measurement.RootPath(), measurement.SandboxPath(), measurement.RunnerPath(), measurement.ImagePath(), measurement.LoopPath(), "/proc/self/ns/net", "/proc/self/ns/mnt"} {
		flags := os.O_RDONLY | unix.O_CLOEXEC
		if i == 0 {
			flags = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC
		}
		f, err := os.OpenFile(path, flags, 0)
		if err != nil {
			return fail(err)
		}
		files = append(files, f)
	}
	gate, writer, err := os.Pipe()
	if err != nil {
		return fail(err)
	}
	files = append(files, gate)
	s.gate = writer
	ready, readyWriter, err := os.Pipe()
	if err != nil {
		return fail(err)
	}
	defer ready.Close()
	files = append(files, readyWriter)
	cmd := exec.Command("/proc/self/fd/5", append([]string{MeasuredNetworkChildCommand}, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin = config.Stdin
	cmd.Stdout = config.Stdout
	cmd.Stderr = config.Stderr
	cmd.ExtraFiles = files
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNET | unix.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(m.UID), Size: 1}, {ContainerID: 65534, HostID: int(m.OverflowUID), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(m.GID), Size: 1}, {ContainerID: 65534, HostID: int(m.OverflowGID), Size: 1}},
		GidMappingsEnableSetgroups: false, Credential: &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL, UseCgroupFD: true, CgroupFD: int(scope.Fd())}
	if err := cmd.Start(); err != nil {
		return fail(err)
	}
	_ = readyWriter.Close()
	s.cmd = cmd
	s.started = true
	go func() { s.exitErr = cmd.Wait(); close(s.done) }()
	s.child, err = np.RetainMappedChild(job.Lease.JobId, cmd.Process, m)
	if err != nil {
		return fail(err)
	}
	// exec returning does not mean Go initialization has finished: the runtime
	// may still adjust process limits. Wait for the owned child's separate ready
	// signal before observing them, without weakening or retrying observations.
	stopReady := context.AfterFunc(ctx, func() { _ = ready.Close() })
	readyOK := awaitMeasuredNetworkToken(ready, time.Now().Add(5*time.Second), 'r')
	stopReady()
	if !readyOK || ctx.Err() != nil {
		return fail(ErrMeasuredNetworkLaunch)
	}
	s.resources, err = np.RetainResources(job, s.child, scope)
	if err != nil || ctx.Err() != nil {
		return fail(errors.Join(err, ctx.Err()))
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-s.authority.Done():
		case <-s.done:
		}
		// Route withdrawal is owned by the outer authority supervisor. Normal
		// child completion must not manufacture an authority-loss failure.
		_ = s.Close(context.Background())
	}()
	return s, nil
}

// Child returns the retained owner needed to construct the native route. The
// process retains ownership; callers must not close or replace this object.
func (s *MeasuredNetworkProcess) Child() *np.ChildNamespaces {
	if s == nil {
		return nil
	}
	return s.child
}

// Release validates actual measurement, resource membership and the exact
// child's authorized kernel route immediately before opening the launch gate.
func (s *MeasuredNetworkProcess) Release(ctx context.Context, link *np.PrivateJobLink) error {
	if s == nil {
		return ErrMeasuredNetworkLaunch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	refuse := func() error {
		s.stopping = true
		if s.gate != nil {
			s.gate.Close()
		}
		return errors.Join(ErrMeasuredNetworkLaunch, s.authority.Withdraw())
	}
	if ctx == nil || ctx.Err() != nil || !s.started || s.stopping || s.closed || s.released || s.gate == nil || s.journal.CheckScope(s.scope) != nil || s.bundle == nil || s.bundle.owner.check(s.bundle, s.job) != nil || !s.bundle.matchesPrivateRoot(s.privateRoot) || s.bundle.checkPrepared(s.mapping) != nil || s.measurement.Validate() != nil || s.resources.ValidateForChild(s.job, s.child) != nil {
		return refuse()
	}
	if s.authority.ObserveInstalledForLink(ctx, s.job, s.child, link) != nil {
		return refuse()
	}
	if n, err := s.gate.Write([]byte("s")); err != nil || n != 1 {
		return refuse()
	}
	if err := s.gate.Close(); err != nil {
		return refuse()
	}
	s.released = true
	s.link = link
	return nil
}

// ObserveRuntime captures a historical observation only while this released
// owner is alive. Failure withdraws authority and triggers owned scope cleanup.
// A past observation is never permission to resume or report guest success.
func (s *MeasuredNetworkProcess) ObserveRuntime(ctx context.Context) (*runtimeidentity.NetworkObservation, error) {
	if s == nil {
		return nil, ErrMeasuredNetworkLaunch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	refuse := func() (*runtimeidentity.NetworkObservation, error) {
		s.stopping = true
		return nil, errors.Join(ErrMeasuredNetworkLaunch, s.authority.Withdraw())
	}
	if ctx == nil || ctx.Err() != nil || !s.started || !s.released || s.stopping || s.closed || s.journal.CheckScope(s.scope) != nil || s.bundle == nil || s.bundle.owner.check(s.bundle, s.job) != nil {
		return refuse()
	}
	observation, err := s.measurement.ObserveNetwork(ctx, s.job, s.child, s.privateRoot, s.resources, s.authority, s.link)
	if err != nil {
		return refuse()
	}
	return observation, nil
}

// Close permanently stops admission and reaps the main process only after the
// owned cgroup is removed. Failure retains descriptors for an explicit retry.
func (s *MeasuredNetworkProcess) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.stopping = true
	if s.gate != nil {
		_ = s.gate.Close()
	}
	if ctx == nil {
		return ErrMeasuredNetworkLaunch
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if s.scope != nil {
		if err := s.journal.Cleanup(ctx, s.scope); err != nil {
			return errors.Join(ErrMeasuredNetworkLaunch, err)
		}
	}
	if s.started {
		select {
		case <-s.done:
		case <-ctx.Done():
			return errors.Join(ErrMeasuredNetworkLaunch, ctx.Err())
		}
	}
	var errs []error
	if s.resources != nil {
		errs = append(errs, s.resources.Close())
	}
	if s.child != nil {
		errs = append(errs, s.child.Close())
	}
	if s.measurement != nil {
		errs = append(errs, s.measurement.Close())
	}
	s.closeErr = errors.Join(errs...)
	s.closed = true
	return s.closeErr
}

// Wait returns the actual runtime exit together with whole-scope cleanup. It
// does not interpret an exit code or a closed main-process handle as cleanup.
func (s *MeasuredNetworkProcess) Wait(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrMeasuredNetworkLaunch
	}
	if !s.started {
		return errors.Join(ErrMeasuredNetworkLaunch, s.Close(context.Background()))
	}
	select {
	case <-s.done:
		return errors.Join(s.exitErr, s.Close(context.Background()))
	case <-ctx.Done():
		return errors.Join(ctx.Err(), s.Close(context.Background()))
	}
}
