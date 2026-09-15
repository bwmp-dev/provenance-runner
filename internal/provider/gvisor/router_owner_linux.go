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

var ErrRouterOwner = errors.New("router_owner_unavailable")

// RouterOwner owns one credential-free direct child in a separately journaled
// cgroup. It creates only the fixed private DNS sockets, no links or public RPC.
// Process cleanup does not prove all external namespace references are closed.
type RouterOwner struct {
	mu              sync.Mutex
	job             *p.JobSpecification
	journal         *np.JobCgroupJournal
	scope           *np.JobCgroup
	measurement     *runtimeidentity.Lease
	child           *np.ChildNamespaces
	resources       *np.RetainedResources
	dns             *routerDNS
	lifetime        *os.File
	cmd             *exec.Cmd
	done            chan struct{}
	started, closed bool
	closeErr        error
}

// StartRouterOwner accepts trusted controller configuration only. Every non-nil
// result owns its newly journaled scope, even on error, until Close succeeds.
func StartRouterOwner(ctx context.Context, job *p.JobSpecification, journal *np.JobCgroupJournal, measurement *runtimeidentity.Lease, mapping np.MappedIdentity) (*RouterOwner, error) {
	return startRouterOwnerWithResources(ctx, job, journal, measurement, mapping, nil)
}

func startRouterOwnerWithResources(ctx context.Context, job *p.JobSpecification, journal *np.JobCgroupJournal, measurement *runtimeidentity.Lease, mapping np.MappedIdentity, resources *np.ControllerResources) (*RouterOwner, error) {
	groups, err := os.Getgroups()
	if ctx == nil || ctx.Err() != nil || job == nil || journal == nil || measurement == nil || os.Getuid() != 0 || os.Geteuid() != 0 || err != nil || len(groups) != 0 {
		return nil, ErrRouterOwner
	}
	job = proto.Clone(job).(*p.JobSpecification)
	args := []string{job.GetLease().GetJobId(), strconv.FormatUint(uint64(mapping.UID), 10), strconv.FormatUint(uint64(mapping.GID), 10), strconv.FormatUint(uint64(mapping.OverflowUID), 10), strconv.FormatUint(uint64(mapping.OverflowGID), 10)}
	if _, ok := routerChildInputs(args); !ok {
		return nil, ErrRouterOwner
	}
	retained, err := measurement.Retain()
	if err != nil {
		return nil, ErrRouterOwner
	}
	s := &RouterOwner{job: job, journal: journal, measurement: retained, done: make(chan struct{})}
	fail := func() (*RouterOwner, error) { return s, errors.Join(ErrRouterOwner, s.Close(context.Background())) }
	s.scope, err = journal.CreateForController(job, resources)
	if err != nil {
		return fail()
	}
	scope, err := s.scope.LaunchFD(job)
	if err != nil {
		return fail()
	}
	defer scope.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		return fail()
	}
	defer reader.Close()
	s.lifetime = writer
	ready, readyWriter, err := os.Pipe()
	if err != nil {
		return fail()
	}
	defer ready.Close()
	defer readyWriter.Close()
	runner, err := os.Open(retained.RunnerPath())
	if err != nil {
		return fail()
	}
	defer runner.Close()
	parentNet, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fail()
	}
	defer parentNet.Close()
	dnsPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return fail()
	}
	dnsParent, dnsChild := os.NewFile(uintptr(dnsPair[0]), "router-dns-receive"), os.NewFile(uintptr(dnsPair[1]), "router-dns-send")
	defer dnsParent.Close()
	defer dnsChild.Close()
	cmd := exec.Command("/proc/self/fd/5", append([]string{RouterChildCommand}, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.ExtraFiles = []*os.File{reader, readyWriter, runner, parentNet, dnsChild}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNET | unix.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(mapping.UID), Size: 1}, {ContainerID: 65534, HostID: int(mapping.OverflowUID), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(mapping.GID), Size: 1}, {ContainerID: 65534, HostID: int(mapping.OverflowGID), Size: 1}},
		GidMappingsEnableSetgroups: false, Credential: &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL, UseCgroupFD: true, CgroupFD: int(scope.Fd())}
	commandDone, err := startOwnedMeasuredCommand(cmd)
	if err != nil {
		return fail()
	}
	s.cmd, s.started = cmd, true
	dnsChild.Close()
	readyWriter.Close()
	go func() { <-commandDone; close(s.done) }()
	stop := context.AfterFunc(ctx, func() { ready.Close() })
	ok := awaitMeasuredNetworkToken(ready, time.Now().Add(5*time.Second), 'r')
	stop()
	if !ok || ctx.Err() != nil {
		return fail()
	}
	s.child, err = np.RetainMappedChild(job.Lease.JobId, cmd.Process, mapping)
	if err != nil {
		return fail()
	}
	s.resources, err = np.RetainResources(job, s.child, scope)
	if err != nil || journal.CheckScope(s.scope) != nil || ctx.Err() != nil {
		return fail()
	}
	s.dns, err = receiveRouterDNS(int(dnsParent.Fd()), s.child, job.Lease.JobId)
	if err != nil {
		return fail()
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-s.done:
		}
		_ = s.Close(context.Background())
	}()
	return s, nil
}

// Child is borrowed for route construction; callers must not close it.
func (s *RouterOwner) Child() *np.ChildNamespaces {
	if s == nil {
		return nil
	}
	return s.child
}

// Done reports holder loss, not completed scope/route cleanup. The outer
// controller must use it to withdraw authority and stop the workload.
func (s *RouterOwner) Done() <-chan struct{} {
	if s == nil || s.done == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return s.done
}

// Close kills the complete owned scope before retiring its durable records.
// It is bounded/retryable; it never claims link or namespace-reference cleanup.
func (s *RouterOwner) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	if s.lifetime != nil {
		_ = s.lifetime.Close()
	}
	var dnsErr error
	if s.dns != nil {
		dnsErr = s.dns.Close()
	}
	if ctx == nil {
		return ErrRouterOwner
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if s.scope != nil {
		if err := s.journal.Cleanup(ctx, s.scope); err != nil {
			return errors.Join(ErrRouterOwner, err, dnsErr)
		}
	}
	if s.started {
		select {
		case <-s.done:
		case <-ctx.Done():
			return ErrRouterOwner
		}
	}
	errs := []error{dnsErr}
	if s.resources != nil {
		errs = append(errs, s.resources.Close())
	}
	if s.child != nil {
		errs = append(errs, s.child.Close())
	}
	if s.measurement != nil {
		errs = append(errs, s.measurement.Close())
	}
	s.closed = true
	if !s.started && s.done != nil {
		close(s.done)
	}
	s.closeErr = errors.Join(errs...)
	return s.closeErr
}
