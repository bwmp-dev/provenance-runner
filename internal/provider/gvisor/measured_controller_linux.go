//go:build linux

package gvisor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// All fields are trusted provisioning, not a root RPC payload. Journal locks
// stay held by their caller; close refuses while this controller owns admission.
type measuredControllerConfig struct {
	Bundles           *measuredBundleJournal
	Uplinks           *np.HostUplinkJournal
	Measurement       *runtimeidentity.Lease
	Boundary          *measuredLocalBoundary
	Tools             np.RouteTools
	Resolver          np.Exchange
	BundleRoot        string
	MaximumInputBytes uint64
}

type measuredController struct {
	mu                      sync.Mutex
	config                  measuredControllerConfig
	measurement             *runtimeidentity.Lease
	resources               *np.ControllerResources
	stopWatch               context.CancelFunc
	watchDone               chan struct{}
	active                  *measuredControllerJob
	ready, stopping, closed bool
}

// A non-nil job owns its partial staging/session until done closes. The global
// slot is not released merely because its main process exited or was cancelled.
type measuredControllerJob struct {
	job        *p.JobSpecification
	observed   bool
	controller *measuredController
	bundle     *measuredBundle
	session    *measuredNetworkSession
	authority  *np.AuthorityRoute
	budget     *measuredSessionBudget
	done       chan struct{}
	reason     error
	outcomeSet bool
	retired    bool
}

func controllerRootMatches(path string, journal *measuredBundleJournal) bool {
	if journal == nil || journal.parent == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return false
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Uid == 0 && st.Mode == unix.S_IFDIR|0711 && uint64(st.Dev) == journal.parentDev && st.Ino == journal.parentIno
}

// Recovery drains owned cgroups/bundles before checking the host uplink. A
// non-nil result owns the controller claim even on failure; retry Close until
// it succeeds. No recovered record authorizes a new or resumed execution.
func newMeasuredController(ctx context.Context, config measuredControllerConfig) (*measuredController, error) {
	groups, err := os.Getgroups()
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || err != nil || len(groups) != 0 || config.Bundles == nil || config.Uplinks == nil || config.Measurement == nil || config.Boundary == nil || config.Boundary.maximum == nil || config.Resolver == nil || config.MaximumInputBytes == 0 || config.MaximumInputBytes > 64<<30 || !controllerRootMatches(config.BundleRoot, config.Bundles) {
		return nil, errMeasuredSession
	}
	measurement, err := config.Measurement.Retain()
	if err != nil {
		return nil, err
	}
	c := &measuredController{config: config, measurement: measurement}
	j := config.Bundles
	j.mu.Lock()
	if j.closed || j.controller != nil || len(j.active) != 0 {
		j.mu.Unlock()
		measurement.Close()
		return nil, errMeasuredSession
	}
	j.controller = c
	j.mu.Unlock()
	c.resources, err = np.RetainControllerResources(j.cgroups, config.Boundary.maximum.Resources)
	if err != nil {
		return c, err
	}
	if err := c.recover(ctx); err != nil {
		return c, err
	}
	if c.resources.Validate() != nil {
		return c, np.ErrResources
	}
	c.ready = true
	watch, stop := context.WithCancel(context.Background())
	c.stopWatch = stop
	c.watchDone = make(chan struct{})
	go c.watchResources(watch)
	return c, nil
}

func (c *measuredController) recover(ctx context.Context) error {
	if c.config.Bundles.recoverForController(ctx, c) != nil || c.config.Uplinks.Recover(ctx) != nil || !controllerRootMatches(c.config.BundleRoot, c.config.Bundles) {
		return errMeasuredSession
	}
	return nil
}

// start accepts only guest execution, verified input descriptors and an already
// authenticated authority owner. It has no host-path, identity, tool or resource
// override. The single slot is reserved before any durable bundle is created.
func (c *measuredController) start(ctx context.Context, job *p.JobSpecification, command measuredGuestCommand, inputs []measuredInput, authority *np.AuthorityRoute, stdin, stdout, stderr *os.File) (*measuredControllerJob, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || job == nil || authority == nil || stdin == nil || stdout == nil || stderr == nil {
		return nil, errMeasuredSession
	}
	job = proto.Clone(job).(*p.JobSpecification)
	c.mu.Lock()
	defer c.mu.Unlock()
	boundary := c.config.Boundary
	if c.closed || c.stopping || !c.ready || c.active != nil || boundary == nil || !c.resourcesReady() || boundary.check(job, boundary.workload, boundary.router) != nil || authority.CheckJob(job) != nil || c.measurement.Validate() != nil || !controllerRootMatches(c.config.BundleRoot, c.config.Bundles) {
		return nil, errMeasuredSession
	}
	budget, err := newMeasuredSessionBudget(ctx, job.EffectivePolicy.PreparationTimeout.AsDuration(), job.EffectivePolicy.ExecutionTimeout.AsDuration())
	if err != nil {
		return nil, err
	}
	owned := &measuredControllerJob{job: job, controller: c, budget: budget, authority: authority, done: make(chan struct{})}
	c.active = owned
	fail := func(err error) (*measuredControllerJob, error) {
		owned.reason = errors.Join(errMeasuredSession, err, context.Cause(budget.ctx))
		owned.outcomeSet = true
		// Authority ownership transfers with the non-nil controller job, even
		// if failure happens before a measured session can be constructed.
		return owned, errors.Join(owned.reason, c.retire(context.Background(), owned))
	}
	owned.bundle, err = c.config.Bundles.createForController(job, c)
	if err != nil {
		return fail(err)
	}
	root := filepath.Join(c.config.BundleRoot, job.Lease.JobId, ".measured-root")
	if err := owned.bundle.prepare(budget.ctx, job, command, root, boundary.workload, inputs, c.config.MaximumInputBytes); err != nil {
		return fail(err)
	}
	launch := MeasuredNetworkLaunchConfig{Job: job, Measurement: c.measurement, Scope: owned.bundle.scope, Journal: c.config.Bundles.cgroups, Bundle: owned.bundle, Authority: authority, Mapping: boundary.workload, PrivateRoot: root, Stdin: stdin, Stdout: stdout, Stderr: stderr}
	owned.session, err = startMeasuredSessionWithBudget(budget.ctx, measuredSessionConfig{Launch: launch, RouterMapping: boundary.router, Uplinks: c.config.Uplinks, Tools: c.config.Tools, Boundary: boundary, Resolver: c.config.Resolver, ControllerResources: c.resources}, budget)
	if err != nil {
		return fail(err)
	}
	go func() {
		reason := owned.session.Wait(context.Background())
		c.mu.Lock()
		defer c.mu.Unlock()
		if !owned.retired {
			if !owned.outcomeSet {
				owned.reason, owned.outcomeSet = reason, true
			}
			_ = c.retire(context.Background(), owned)
		}
	}()
	return owned, nil
}

// retire runs with the controller mutex held. Failed cleanup preserves the
// active slot and all remaining handles for an explicit retry.
func (c *measuredController) retire(ctx context.Context, owned *measuredControllerJob) error {
	if owned.retired {
		return nil
	}
	if c.active != owned {
		return errMeasuredSession
	}
	owned.budget.close()
	var cleanupErr error
	if owned.authority != nil {
		if err := owned.authority.Close(); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		} else {
			owned.authority = nil
		}
	}
	if owned.session != nil {
		cleanupErr = errors.Join(cleanupErr, owned.session.Close(ctx))
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	if owned.bundle != nil && c.config.Bundles.cleanup(ctx, owned.bundle) != nil {
		return errMeasuredSession
	}
	if c.recover(ctx) != nil {
		return errMeasuredSession
	}
	_ = c.resourcesReady()
	owned.retired = true
	c.active = nil
	close(owned.done)
	return nil
}

func (j *measuredControllerJob) Release(ctx context.Context) error {
	if j == nil || j.controller == nil {
		return errMeasuredSession
	}
	c := j.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if j.retired || c.active != j || c.stopping || j.session == nil || !c.resourcesReady() {
		return errMeasuredSession
	}
	return j.session.Release(ctx)
}

func (j *measuredControllerJob) Close(ctx context.Context) error {
	if j == nil {
		return nil
	}
	if ctx == nil || j.controller == nil {
		return errMeasuredSession
	}
	c := j.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if j.retired {
		return nil
	}
	j.recordCloseOutcome()
	return c.retire(ctx, j)
}

func (j *measuredControllerJob) Wait(ctx context.Context) error {
	if j == nil || ctx == nil || j.controller == nil || j.done == nil {
		return errMeasuredSession
	}
	select {
	case <-j.done:
		return j.reason
	case <-ctx.Done():
		return errors.Join(ctx.Err(), j.Close(context.Background()))
	}
}

func (c *measuredController) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		return errMeasuredSession
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.stopping = true
	c.ready = false
	if c.stopWatch != nil {
		c.stopWatch()
	}
	done := c.watchDone
	c.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if c.active != nil {
		c.active.recordCloseOutcome()
		if err := c.retire(ctx, c.active); err != nil {
			return err
		}
	}
	if c.recover(ctx) != nil {
		return errMeasuredSession
	}
	if err := errors.Join(c.resources.Close(), c.measurement.Close()); err != nil {
		return errMeasuredSession
	}
	j := c.config.Bundles
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.controller != c || len(j.active) != 0 {
		return errMeasuredSession
	}
	j.controller = nil
	c.closed = true
	return nil
}

// resourcesReady runs with the controller mutex held. Drift permanently stops
// admission and cancels the active session; restoring values cannot resume it.
func (c *measuredController) resourcesReady() bool {
	if c.resources.Validate() == nil {
		return true
	}
	c.ready = false
	c.stopping = true
	if c.active != nil {
		c.active.budget.cancel(np.ErrResources)
	}
	return false
}

func (c *measuredController) watchResources(ctx context.Context) {
	defer close(c.watchDone)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.resources.Validate() != nil {
				c.mu.Lock()
				if !c.closed {
					_ = c.resourcesReady()
				}
				c.mu.Unlock()
				return
			}
		}
	}
}

func (j *measuredControllerJob) ObserveRuntime(ctx context.Context) (*runtimeidentity.NetworkObservation, error) {
	if j == nil || j.controller == nil {
		return nil, errMeasuredSession
	}
	c := j.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if j.retired || c.active != j || c.stopping || j.session == nil || !c.resourcesReady() {
		return nil, errMeasuredSession
	}
	observation, err := j.session.ObserveRuntime(ctx)
	if err != nil || !c.resourcesReady() {
		return nil, errors.Join(err, np.ErrResources)
	}
	j.observed = true
	return observation, nil
}

// completedProcessExit reports the owned process's kernel exit only after every
// controller-owned object has retired. It does not replace Wait's cancellation,
// authority or infrastructure failure: exit zero alone is not a successful job.
// In particular, no code supplied in a guest outcome frame is consulted here.
func (j *measuredControllerJob) completedProcessExit() (int, error) {
	code, _, err := j.completedProcessOutcome()
	return code, err
}

// Preserve infrastructure errors without classifying an ordinary nonzero guest
// exit as infrastructure failure. Only the exact owned command's ExitError can
// be treated as a process outcome; joined or substituted errors remain failures.
func (j *measuredControllerJob) completedProcessOutcome() (int, bool, error) {
	if j == nil || j.controller == nil {
		return 0, true, errMeasuredSession
	}
	c := j.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if !j.retired || j.session == nil || j.session.process == nil {
		return 0, true, errMeasuredSession
	}
	process := j.session.process
	select {
	case <-process.done:
	default:
		return 0, true, errMeasuredSession
	}
	if process.cmd == nil || process.cmd.ProcessState == nil {
		return 0, true, errMeasuredSession
	}
	code := process.cmd.ProcessState.ExitCode()
	if code < 0 || code > 255 {
		return 0, true, errMeasuredSession
	}
	infrastructure := j.reason != nil
	if reason, ok := j.reason.(*exec.ExitError); ok {
		actual, sameType := process.exitErr.(*exec.ExitError)
		if sameType && reason == actual && reason.ProcessState == process.cmd.ProcessState {
			infrastructure = false
		}
	}
	return code, infrastructure, nil
}

// Called with the controller mutex held. Cleanup retries do not turn an
// already completed normal session into a cancellation result.
func (j *measuredControllerJob) recordCloseOutcome() {
	if j.outcomeSet {
		return
	}
	j.reason, j.outcomeSet = context.Canceled, true
	if j.session != nil {
		select {
		case <-j.session.done:
			j.reason = j.session.reason
		default:
		}
	}
}
