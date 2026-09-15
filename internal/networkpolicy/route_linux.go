//go:build linux

package networkpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// ProtectedRouteTool contains an already opened operator-selected executable
// and its trusted digest. Neither identity may originate in a workload request.
// The actuator duplicates and retains the object, not the mutable source path.
type ProtectedRouteTool struct {
	File   *os.File
	SHA256 [32]byte
}
type RouteTools struct{ NSenter, NFT, IP ProtectedRouteTool }

// RetainedRoute executes sealed firewall changes only inside the retained
// routing child's namespace. It never switches the controller's own namespace.
// Child creation, peer wiring, policy authority and runtime measurement are
// separate owning boundaries; this actuator does not advertise a capability.
type RetainedRoute struct {
	mu                                         sync.Mutex
	job                                        string
	router, workload                           *ChildNamespaces
	network                                    *os.File
	tools                                      RouteTools
	installed, withdrawn, disconnected, closed bool
	kernelIdentity                             [32]byte
}

func (r *RetainedRoute) JobID() string {
	if r == nil {
		return ""
	}
	return r.job
}

func NewRetainedRoute(job string, router, workload *ChildNamespaces, selected RouteTools) (result *RetainedRoute, err error) {
	if router == nil || workload == nil || router == workload || !separateRouteMappings(router.mapping, workload.mapping) || router.Validate(job) != nil || workload.Validate(job) != nil {
		return nil, ErrNamespace
	}
	r := &RetainedRoute{job: job, router: router, workload: workload}
	defer func() {
		if err != nil {
			_ = r.Close()
		}
	}()
	r.network, err = router.NetworkForJob(job)
	if err != nil {
		return nil, ErrNamespace
	}
	peer, err := workload.NetworkForJob(job)
	if err != nil {
		return nil, ErrNamespace
	}
	defer peer.Close()
	if sameNamespace(r.network, peer, unix.CLONE_NEWNET) {
		return nil, ErrNamespace
	}
	for _, pair := range []struct {
		source ProtectedRouteTool
		target *ProtectedRouteTool
	}{{selected.NSenter, &r.tools.NSenter}, {selected.NFT, &r.tools.NFT}, {selected.IP, &r.tools.IP}} {
		if !validRouteTool(pair.source) {
			return nil, ErrActuation
		}
		fd, e := unix.FcntlInt(pair.source.File.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if e != nil {
			return nil, ErrActuation
		}
		*pair.target = ProtectedRouteTool{File: os.NewFile(uintptr(fd), "retained-route-tool"), SHA256: pair.source.SHA256}
		if !validRouteTool(*pair.target) {
			return nil, ErrActuation
		}
	}
	return r, nil
}

func separateRouteMappings(a, b MappedIdentity) bool {
	for _, uid := range []uint32{a.UID, a.OverflowUID} {
		if uid == b.UID || uid == b.OverflowUID {
			return false
		}
	}
	for _, gid := range []uint32{a.GID, a.OverflowGID} {
		if gid == b.GID || gid == b.OverflowGID {
			return false
		}
	}
	return true
}

func validRouteTool(tool ProtectedRouteTool) bool {
	if tool.File == nil || tool.SHA256 == ([32]byte{}) {
		return false
	}
	flags, err := unix.FcntlInt(tool.File.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return false
	}
	var stat unix.Stat_t
	if unix.Fstat(int(tool.File.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&06022 != 0 || stat.Mode&0111 == 0 || stat.Size < 4 || stat.Size > 512<<20 {
		return false
	}
	var magic [4]byte
	if _, err := tool.File.ReadAt(magic[:], 0); err != nil || magic != ([4]byte{0x7f, 'E', 'L', 'F'}) {
		return false
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(tool.File, 0, stat.Size)); err != nil {
		return false
	}
	return bytes.Equal(h.Sum(nil), tool.SHA256[:])
}

type routeOutput struct{ buffer bytes.Buffer }

func (b *routeOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *routeOutput) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 65536 {
		return 0, ErrActuation
	}
	return b.buffer.Write(p)
}

func (r *RetainedRoute) execute(ctx context.Context, tool ProtectedRouteTool, input string, args ...string) ([]byte, error) {
	if ctx == nil || r.closed {
		return nil, ErrActuation
	}
	return executeRetainedTool(ctx, r.network, r.tools.NSenter, tool, nil, input, args...)
}

func executeRetainedTool(ctx context.Context, network *os.File, nsenter, tool ProtectedRouteTool, extra []*os.File, input string, args ...string) ([]byte, error) {
	if ctx == nil || network == nil || !validRouteTool(nsenter) || !validRouteTool(tool) {
		return nil, ErrActuation
	}
	ctx, cancel := context.WithTimeout(ctx, routeOperationTimeout)
	defer cancel()
	// ExtraFiles assigns exactly 3=namespace, 4=nsenter, 5=target executable.
	// -F forbids an intermediate fork; cancellation kills the exact executing
	// process. No PID pathname, namespace name, shell or ambient PATH is used.
	cmd := exec.CommandContext(ctx, "/proc/self/fd/4")
	cmd.Args = append([]string{"nsenter", "-F", "--preserve-credentials", "-n/proc/self/fd/3", "--", "/proc/self/fd/5"}, args...)
	cmd.ExtraFiles = append([]*os.File{network, nsenter.File, tool.File}, extra...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.Stdin = bytes.NewBufferString(input)
	var output routeOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		if ctx.Err() != nil {
			return nil, &actuationFailure{actuationCommandCancelled}
		}
		return nil, &actuationFailure{actuationCommandRefused}
	}
	return output.Bytes(), nil
}

func (r *RetainedRoute) routingTopology(ctx context.Context) error {
	raw, err := r.execute(ctx, r.tools.IP, "", "-j", "-d", "link", "show")
	if err != nil {
		return err
	}
	var links []struct {
		Name  string   `json:"ifname"`
		Flags []string `json:"flags"`
		Info  struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if json.Unmarshal(raw, &links) != nil || len(links) != 3 {
		return ErrNamespace
	}
	seen := map[string]bool{}
	for _, link := range links {
		if seen[link.Name] || (link.Name != "lo" && link.Name != "job0" && link.Name != "wan0") {
			return ErrNamespace
		}
		seen[link.Name] = true
		if link.Name == "lo" {
			continue
		}
		up := false
		for _, flag := range link.Flags {
			if flag == "UP" {
				up = true
			}
		}
		if !up || link.Info.Kind != "veth" {
			return ErrNamespace
		}
	}
	return nil
}

func (r *RetainedRoute) Apply(ctx context.Context, change FirewallChange) error {
	if r == nil {
		return ErrActuation
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || change.job != r.job || change.program == "" || len(change.program) > 1<<20 {
		return ErrActuation
	}
	switch change.kind {
	case routeInstall, routeRefresh:
		if r.withdrawn || r.disconnected || (change.kind == routeInstall && r.installed) || (change.kind == routeRefresh && !r.installed) || r.router.Validate(r.job) != nil || r.workload.Validate(r.job) != nil {
			return ErrNamespace
		}
		if err := r.routingTopology(ctx); err != nil {
			return err
		}
		if change.kind == routeRefresh {
			identity, err := r.readKernelIdentity(ctx)
			if err != nil {
				return err
			}
			if identity != r.kernelIdentity {
				return &actuationFailure{actuationIdentityChanged}
			}
		}
		if change.kind == routeInstall {
			raw, err := r.execute(ctx, r.tools.NFT, "", "-j", "list", "tables")
			if err != nil {
				return err
			}
			var list struct {
				Items []map[string]json.RawMessage `json:"nftables"`
			}
			if json.Unmarshal(raw, &list) != nil {
				return ErrActuation
			}
			for _, item := range list.Items {
				if _, exists := item["table"]; exists {
					return ErrNamespace
				}
			}
		}
	case routeWithdraw, routeRemove:
		// The child may already have exited. Cleanup still uses only the owned
		// retained object, never a new lookup by its reusable process number.
		r.withdrawn = true
		if change.kind == routeRemove && !r.disconnected {
			return ErrActuation
		}
	default:
		return ErrActuation
	}
	if _, err := r.execute(ctx, r.tools.NFT, change.program, "-n", "-f", "-"); err != nil {
		return err
	}
	if change.kind == routeInstall {
		r.installed = true
	}
	if change.kind == routeInstall || change.kind == routeRefresh {
		identity, err := r.readKernelIdentity(ctx)
		if err != nil {
			return err
		}
		r.kernelIdentity = identity
	}
	if (change.kind == routeInstall || change.kind == routeRefresh) && (r.router.Validate(r.job) != nil || r.workload.Validate(r.job) != nil) {
		return ErrNamespace
	}
	return nil
}

func (r *RetainedRoute) readKernelIdentity(ctx context.Context) ([32]byte, error) {
	raw, err := r.execute(ctx, r.tools.NFT, "", "-j", "-n", "list", "ruleset")
	if err != nil {
		return [32]byte{}, err
	}
	identity, err := kernelRulesetIdentity(raw, r.job)
	if err != nil {
		return [32]byte{}, &actuationFailure{actuationReadbackInvalid}
	}
	return identity, nil
}

// ObserveInstalled proves a current owned kernel snapshot, not caller-supplied
// labels. It is not by itself a measured Sentry launch or authority observation.
func (r *RetainedRoute) ObserveInstalled(ctx context.Context, job string) error {
	return r.observeInstalled(ctx, job, nil, false)
}

func (r *RetainedRoute) observeInstalled(ctx context.Context, job string, child *ChildNamespaces, requireChild bool) error {
	if r == nil {
		return ErrNamespace
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if requireChild && (child == nil || child != r.workload) {
		return ErrNamespace
	}
	if r.closed || !r.installed || r.withdrawn || r.disconnected || job != r.job || r.router.Validate(job) != nil || r.workload.Validate(job) != nil {
		return ErrNamespace
	}
	if err := r.routingTopology(ctx); err != nil {
		return err
	}
	identity, err := r.readKernelIdentity(ctx)
	if err != nil || identity != r.kernelIdentity || r.router.Validate(job) != nil || r.workload.Validate(job) != nil {
		return ErrActuation
	}
	return nil
}

func (r *RetainedRoute) Disconnect(ctx context.Context) error {
	if r == nil {
		return ErrActuation
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrActuation
	}
	r.withdrawn = true
	if r.disconnected {
		return nil
	}
	if _, err := r.execute(ctx, r.tools.IP, "", "link", "set", "job0", "down"); err != nil {
		return err
	}
	r.disconnected = true
	return nil
}

// Close releases retained descriptors only; it neither deletes peer wiring nor
// kills children. The owner must finish RouteSession.Close and process teardown
// and must not interpret reference cleanup as released workload capacity.
func (r *RetainedRoute) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var result error
	for _, f := range []*os.File{r.network, r.tools.NSenter.File, r.tools.NFT.File, r.tools.IP.File} {
		if f != nil && f.Close() != nil {
			result = ErrActuation
		}
	}
	return result
}
