//go:build linux

package measuredservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/provider/gvisor"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	"golang.org/x/sys/unix"
)

// Daemon owns provisioning handles, including partial initialization. A caller
// must retry Close until successful before relinquishing process ownership.
// OpenDaemon never creates a mount, cgroup parent, identity allocation or quota.
type Daemon struct {
	mu          sync.Mutex
	ctx         context.Context
	stop        context.CancelFunc
	listener    *cc.RootListener
	server      *Server
	controller  *gvisor.MeasuredController
	measurement *runtimeidentity.Lease
	groups      *np.JobCgroupJournal
	bundles     *gvisor.MeasuredBundleJournal
	uplinks     *np.HostUplinkJournal
	files       []*os.File
	closed      bool
	serving     bool
}

// Protected root-owned objects may be below sticky root-owned parents: every
// intervening child is also root-owned, so an unprivileged user cannot replace
// it. No symlink is traversed. The configuration file itself uses stricter,
// non-writable parents in LoadDaemonConfig.
func openDaemonObject(path string, directory bool, mode uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || len(path) > 4096 {
		return nil, ErrService
	}
	parent, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrService
	}
	defer func() { unix.Close(parent) }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, component := range parts {
		last := i == len(parts)-1
		flags := uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC)
		if last {
			flags = unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC
			if directory {
				flags |= unix.O_DIRECTORY
			}
		}
		fd, err := unix.Openat2(parent, component, &unix.OpenHow{Flags: flags, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return nil, ErrService
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || (st.Mode&0022 != 0 && (last || st.Mode&unix.S_ISVTX == 0)) || st.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
			unix.Close(fd)
			return nil, ErrService
		}
		if last {
			kind := uint32(unix.S_IFREG)
			if directory {
				kind = unix.S_IFDIR
			}
			if st.Mode&unix.S_IFMT != kind || (mode != 0 && st.Mode != kind|mode) {
				unix.Close(fd)
				return nil, ErrService
			}
			return os.NewFile(uintptr(fd), "root provisioning object"), nil
		}
		unix.Close(parent)
		parent = fd
	}
	return nil, ErrService
}

func OpenDaemon(ctx context.Context, config DaemonConfig) (*Daemon, error) {
	groups, err := os.Getgroups()
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || err != nil || len(groups) != 0 {
		return nil, ErrService
	}
	boundary, err := config.boundary()
	if err != nil {
		return nil, ErrService
	}
	ctx, stop := context.WithCancel(ctx)
	d := &Daemon{ctx: ctx, stop: stop}
	fail := func() (*Daemon, error) { return d, ErrService }
	d.measurement, err = runtimeidentity.AcquirePinned(ctx, config.SandboxPath, config.RootPath, config.ImagePath, runtimeidentity.ExpectedObjects{RunnerSHA256: config.RunnerSHA256, SandboxSHA256: config.SandboxSHA256, RootFSSHA256: config.RootFSSHA256}, config.LoopPath)
	if err != nil {
		return fail()
	}
	snapshot := d.measurement.Snapshot()
	if snapshot.RunnerExecutableSHA256 != config.RunnerSHA256 || snapshot.SandboxExecutableSHA256 != config.SandboxSHA256 || snapshot.RootFS.SHA256 != config.RootFSSHA256 || d.measurement.ValidatePaperGuestTarget() != nil {
		return fail()
	}
	open := func(path string, directory bool, mode uint32) (*os.File, error) {
		file, err := openDaemonObject(path, directory, mode)
		if err == nil {
			d.files = append(d.files, file)
		}
		return file, err
	}
	tool := func(config DaemonTool) (np.ProtectedRouteTool, error) {
		file, err := open(config.Path, false, 0)
		if err != nil {
			return np.ProtectedRouteTool{}, ErrService
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(file, (32<<20)+1))
		if err != nil || n == 0 || n > 32<<20 || hex.EncodeToString(h.Sum(nil)) != config.SHA256 {
			return np.ProtectedRouteTool{}, ErrService
		}
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		return np.ProtectedRouteTool{File: file, SHA256: digest}, nil
	}
	var tools np.RouteTools
	if tools.IP, err = tool(config.IP); err != nil {
		return fail()
	}
	if tools.NFT, err = tool(config.NFT); err != nil {
		return fail()
	}
	if tools.NSenter, err = tool(config.NSenter); err != nil {
		return fail()
	}
	parent, err := open(config.CgroupParent, true, 0)
	if err != nil {
		return fail()
	}
	groupState, err := open(config.CgroupState, true, 0700)
	if err != nil {
		return fail()
	}
	bundleRoot, err := open(config.BundleRoot, true, 0711)
	if err != nil {
		return fail()
	}
	bundleState, err := open(config.BundleState, true, 0700)
	if err != nil {
		return fail()
	}
	uplinkState, err := open(config.UplinkState, true, 0700)
	if err != nil {
		return fail()
	}
	socketRoot, err := open(config.SocketDirectory, true, 0711)
	if err != nil {
		return fail()
	}
	d.groups, err = np.OpenJobCgroupJournal(parent, groupState)
	if err != nil {
		return fail()
	}
	if config.SecretRoot != "" {
		secretRoot, openErr := open(config.SecretRoot, true, 0711)
		if openErr != nil {
			return fail()
		}
		d.bundles, err = gvisor.OpenMeasuredBundleJournalWithSecrets(bundleRoot, bundleState, secretRoot, d.groups)
	} else {
		d.bundles, err = gvisor.OpenMeasuredBundleJournal(bundleRoot, bundleState, d.groups)
	}
	if err != nil {
		return fail()
	}
	d.uplinks, err = np.OpenHostUplinkJournal(uplinkState, tools)
	if err != nil {
		return fail()
	}
	resolver, _ := netip.ParseAddrPort(config.Resolver)
	d.controller, err = gvisor.OpenMeasuredController(ctx, gvisor.MeasuredControllerConfig{Bundles: d.bundles, Uplinks: d.uplinks, Measurement: d.measurement, Boundary: boundary, Tools: tools, Resolver: np.TCPResolver{Endpoint: resolver}, BundleRoot: config.BundleRoot, MaximumInputBytes: config.MaximumInputBytes})
	if err != nil {
		return fail()
	}
	source, err := paper.NewRuntimeSource(config.RuntimeOrigin, config.RuntimePublicKey)
	if err != nil {
		return fail()
	}
	d.server, err = New(ctx, Config{Controller: d.controller, Measurement: d.measurement, RuntimeSource: source, WorkerUID: config.WorkerUID, MaximumInputBytes: config.MaximumInputBytes, EnableSecrets: config.SecretRoot != ""})
	if err != nil {
		return fail()
	}
	d.listener, err = cc.OpenRootListener(socketRoot, config.WorkerUID, config.WorkerGID)
	if err != nil {
		return fail()
	}
	return d, nil
}

// Serve serializes acceptance with execution; no unbounded goroutine or FD
// queue is created. A bad request does not poison a successfully retired owner.
// A non-timeout listener failure or failed controller stops further admission.
func (d *Daemon) Serve() error {
	if d == nil {
		return ErrService
	}
	d.mu.Lock()
	if d.serving || d.closed {
		d.mu.Unlock()
		return ErrService
	}
	listener, server, ctx := d.listener, d.server, d.ctx
	d.serving = true
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.serving = false; d.mu.Unlock() }()
	if listener == nil || server == nil || ctx == nil {
		return ErrService
	}
	for ctx.Err() == nil {
		channel, err := listener.Accept(time.Now().Add(time.Second))
		if err != nil {
			var timed net.Error
			if errors.As(err, &timed) && timed.Timeout() {
				continue
			}
			return ErrService
		}
		_ = server.Serve(ctx, channel)
		server.mu.Lock()
		failed := server.failed || server.closed || server.controller.CheckIdle() != nil
		server.mu.Unlock()
		if failed {
			return ErrService
		}
	}
	return ctx.Err()
}

// Close stops admission first and retains every remaining owner after failure.
// It never unmounts provisioned roots or deletes externally supplied paths.
func (d *Daemon) Close(ctx context.Context) error {
	if d == nil {
		return nil
	}
	if ctx == nil {
		return ErrService
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	if d.stop != nil {
		d.stop()
	}
	var listenerErr error
	if d.listener != nil {
		listenerErr = d.listener.Close()
	}
	if d.server != nil {
		if err := d.server.Close(ctx); err != nil {
			return ErrService
		}
		d.server = nil
	}
	if d.controller != nil {
		if err := d.controller.Close(ctx); err != nil {
			return ErrService
		}
		d.controller = nil
	}
	if listenerErr != nil {
		return ErrService
	}
	d.listener = nil
	if d.uplinks != nil {
		if d.uplinks.Close() != nil {
			return ErrService
		}
		d.uplinks = nil
	}
	if d.bundles != nil {
		if d.bundles.Close() != nil {
			return ErrService
		}
		d.bundles = nil
	}
	if d.groups != nil {
		if d.groups.Close() != nil {
			return ErrService
		}
		d.groups = nil
	}
	if d.measurement != nil {
		if d.measurement.Close() != nil {
			return ErrService
		}
		d.measurement = nil
	}
	var err error
	for _, file := range d.files {
		err = errors.Join(err, file.Close())
	}
	d.files = nil
	if err != nil {
		return ErrService
	}
	d.closed = true
	return nil
}
