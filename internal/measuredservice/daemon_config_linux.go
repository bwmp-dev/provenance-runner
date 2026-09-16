//go:build linux

package measuredservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/provider/gvisor"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
)

// DaemonConfig is root-owned provisioning, never a worker request. Paths refer
// to already provisioned objects; loading this file mounts or creates nothing.
// It contains public verification material, not gateway/platform credentials.
type DaemonConfig struct {
	Version           int               `json:"version"`
	WorkerUID         uint32            `json:"workerUid"`
	WorkerGID         uint32            `json:"workerGid"`
	SocketDirectory   string            `json:"socketDirectory"`
	CgroupParent      string            `json:"cgroupParent"`
	CgroupState       string            `json:"cgroupState"`
	BundleRoot        string            `json:"bundleRoot"`
	BundleState       string            `json:"bundleState"`
	SecretRoot        string            `json:"secretRoot,omitempty"`
	UplinkState       string            `json:"uplinkState"`
	SandboxPath       string            `json:"sandboxPath"`
	RootPath          string            `json:"rootPath"`
	ImagePath         string            `json:"imagePath"`
	LoopPath          string            `json:"loopPath"`
	RunnerSHA256      string            `json:"runnerSha256"`
	SandboxSHA256     string            `json:"sandboxSha256"`
	RootFSSHA256      string            `json:"rootfsSha256"`
	IP                DaemonTool        `json:"ip"`
	NFT               DaemonTool        `json:"nft"`
	NSenter           DaemonTool        `json:"nsenter"`
	RuntimeOrigin     string            `json:"runtimeOrigin"`
	RuntimePublicKey  string            `json:"runtimePublicKey"`
	Resolver          string            `json:"resolver"`
	Workload          np.MappedIdentity `json:"workload"`
	Router            np.MappedIdentity `json:"router"`
	SensitiveNetworks []string          `json:"sensitiveNetworks"`
	MaximumTTLSeconds uint32            `json:"maximumTtlSeconds"`
	MaximumInputBytes uint64            `json:"maximumInputBytes"`
	MaximumPolicy     json.RawMessage   `json:"maximumPolicy"`
}

type DaemonTool struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func daemonDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && value == strings.ToLower(value) && !bytes.Equal(raw, make([]byte, 32))
}

func (c DaemonConfig) boundary() (*gvisor.MeasuredLocalBoundary, error) {
	if c.Version != 1 || c.WorkerUID == 0 || c.WorkerGID == 0 || c.WorkerUID == ^uint32(0) || c.WorkerGID == ^uint32(0) || c.MaximumInputBytes == 0 || c.MaximumInputBytes > 64<<30 {
		return nil, ErrService
	}
	for _, value := range []string{c.RunnerSHA256, c.SandboxSHA256, c.RootFSSHA256, c.IP.SHA256, c.NFT.SHA256, c.NSenter.SHA256} {
		if !daemonDigest(value) {
			return nil, ErrService
		}
	}
	paths := []string{c.SocketDirectory, c.CgroupParent, c.CgroupState, c.BundleRoot, c.BundleState, c.UplinkState, c.SandboxPath, c.RootPath, c.ImagePath, c.LoopPath, c.IP.Path, c.NFT.Path, c.NSenter.Path}
	if c.SecretRoot != "" {
		paths = append(paths, c.SecretRoot)
	}
	seen := make(map[string]bool)
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || len(path) > 4096 || strings.IndexByte(path, 0) >= 0 || seen[path] {
			return nil, ErrService
		}
		seen[path] = true
	}
	for _, mapping := range []np.MappedIdentity{c.Workload, c.Router} {
		if mapping.UID == c.WorkerUID || mapping.OverflowUID == c.WorkerUID || mapping.GID == c.WorkerGID || mapping.OverflowGID == c.WorkerGID {
			return nil, ErrService
		}
	}
	if _, err := paper.NewRuntimeSource(c.RuntimeOrigin, c.RuntimePublicKey); err != nil {
		return nil, ErrService
	}
	resolver, err := netip.ParseAddrPort(c.Resolver)
	if err != nil || !resolver.IsValid() || resolver.Port() == 0 || resolver.Addr().Is4In6() || resolver.Addr().Zone() != "" || resolver.Addr().IsUnspecified() || resolver.Addr().IsMulticast() {
		return nil, ErrService
	}
	var sensitive []netip.Prefix
	for _, raw := range c.SensitiveNetworks {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, ErrService
		}
		sensitive = append(sensitive, prefix)
	}
	policy := new(p.EffectivePolicy)
	if (protojson.UnmarshalOptions{DiscardUnknown: false, RecursionLimit: 16}).Unmarshal(c.MaximumPolicy, policy) != nil {
		return nil, ErrService
	}
	return gvisor.NewMeasuredLocalBoundary(policy, c.Workload, c.Router, sensitive, time.Duration(c.MaximumTTLSeconds)*time.Second)
}

// Reject duplicate keys at every depth before typed decoding. JSON is bounded
// independently of filesystem permissions; no parser error includes its input.
func daemonJSON(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 64<<10 || !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 16 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return true
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				name = strings.ToLower(name)
				if err != nil || !ok || seen[name] || !walk(depth+1) {
					return false
				}
				seen[name] = true
			}
		case '[':
			for d.More() {
				if !walk(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		end, err := d.Token()
		return err == nil && ((delimiter == '{' && end == json.Delim('}')) || (delimiter == '[' && end == json.Delim(']')))
	}
	if !walk(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func decodeDaemonConfig(raw []byte) (*DaemonConfig, error) {
	if !daemonJSON(raw) {
		return nil, ErrService
	}
	var config DaemonConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&config) != nil {
		return nil, ErrService
	}
	if _, err := config.boundary(); err != nil {
		return nil, ErrService
	}
	return &config, nil
}

// Open each component beneath retained descriptors; root-owned, non-writable
// parents prevent unprivileged path replacement. The final file must be private
// root-owned regular storage, never a FIFO, symlink or multiply-linked file.
func LoadDaemonConfig(ctx context.Context, path string) (*DaemonConfig, error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || len(path) > 4096 {
		return nil, ErrService
	}
	parent, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrService
	}
	defer func() { unix.Close(parent) }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, component := range parts[:len(parts)-1] {
		fd, err := unix.Openat2(parent, component, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return nil, ErrService
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			unix.Close(fd)
			return nil, ErrService
		}
		unix.Close(parent)
		parent = fd
	}
	fd, err := unix.Openat2(parent, parts[len(parts)-1], &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, ErrService
	}
	file := os.NewFile(uintptr(fd), "root daemon configuration")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Uid != 0 || before.Mode != unix.S_IFREG|0600 || before.Nlink != 1 || before.Size <= 0 || before.Size > 64<<10 {
		return nil, ErrService
	}
	raw, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(len(raw)) != before.Size || ctx.Err() != nil {
		return nil, ErrService
	}
	return decodeDaemonConfig(raw)
}
