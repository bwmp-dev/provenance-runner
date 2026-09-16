//go:build linux

package measuredservice

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
)

func fixtureTCPResolver(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(length[:]))
				if size < 12 || size > 4096 {
					return
				}
				query := make([]byte, size)
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				answer, err := (fixtureResolver{}).Exchange(context.Background(), query)
				if err != nil || len(answer) > 4096 {
					return
				}
				binary.BigEndian.PutUint16(length[:], uint16(len(answer)))
				_, _ = conn.Write(append(length[:], answer...))
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return listener.Addr().String()
}

// This helper runs only inside the disposable root kernel fixture. Public
// synthetic pins are selected by that fixture, never by an execution request.
func openFixtureDaemon(t *testing.T, ctx context.Context, socket, state, bundle string, lease *runtimeidentity.Lease, tools np.RouteTools, source *paper.RuntimeSource, job *p.JobSpecification, maximumInput uint64) *Daemon {
	t.Helper()
	alias, err := os.MkdirTemp("/tmp", "daemon-journals-")
	if err != nil {
		t.Fatal(err)
	}
	if unix.Mount(state, alias, "", unix.MS_BIND, "") != nil {
		t.Fatal("protected persistent daemon state alias")
	}
	t.Cleanup(func() {
		if unix.Unmount(alias, 0) != nil {
			t.Error("daemon state alias retained")
			return
		}
		if os.Remove(alias) != nil {
			t.Error("daemon state mountpoint retained")
		}
	})
	config := fixtureDaemonConfig(t)
	if len(job.TestSecrets) > 0 {
		config.SecretRoot = filepath.Join(socket, "secrets")
	}
	config.MaximumInputBytes = maximumInput
	config.SocketDirectory = socket
	config.CgroupParent = "/sys/fs/cgroup/provenance-fixture-jobs"
	config.CgroupState = filepath.Join(alias, "cgroups")
	config.BundleState = filepath.Join(alias, "bundles")
	config.UplinkState = filepath.Join(alias, "uplinks")
	config.BundleRoot = bundle
	config.SandboxPath = "/tmp/provenance-runtime-fixture/runsc"
	config.RootPath = "/tmp/provenance-runtime-fixture/mount"
	config.ImagePath = "/tmp/provenance-runtime-fixture/image.squashfs"
	var device unix.Stat_t
	if unix.Stat(lease.LoopPath(), &device) != nil || device.Mode&unix.S_IFMT != unix.S_IFBLK {
		t.Fatal("fixture loop identity")
	}
	config.LoopPath = fmt.Sprintf("/dev/loop%d", unix.Minor(device.Rdev))
	snapshot := lease.Snapshot()
	config.RunnerSHA256, config.SandboxSHA256, config.RootFSSHA256 = snapshot.RunnerExecutableSHA256, snapshot.SandboxExecutableSHA256, snapshot.RootFS.SHA256
	tool := func(value np.ProtectedRouteTool) DaemonTool {
		path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", value.File.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		return DaemonTool{Path: path, SHA256: hex.EncodeToString(value.SHA256[:])}
	}
	config.IP, config.NFT, config.NSenter = tool(tools.IP), tool(tools.NFT), tool(tools.NSenter)
	config.RuntimeOrigin, config.RuntimePublicKey = source.Origin, hex.EncodeToString(source.PublicKey)
	config.Resolver = fixtureTCPResolver(t)
	config.MaximumPolicy, err = protojson.Marshal(job.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	// /dev is a container-private writable filesystem with protected parents;
	// no host device is modified. Only this fresh directory and regular file
	// are created, and cleanup removes their exact names without recursion.
	directory, err := os.MkdirTemp("/dev", "provenance-config-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "daemon.json")
	t.Cleanup(func() {
		if os.Remove(path) != nil {
			t.Error("fixture config retained")
		}
		if os.Remove(directory) != nil {
			t.Error("fixture config directory retained")
		}
	})
	raw, err := json.Marshal(config)
	if err != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("fixture root config")
	}
	loaded, err := LoadDaemonConfig(ctx, path)
	if err != nil {
		t.Fatal("root-owned daemon config", err)
	}
	t.Run("root-config-permissions", func(t *testing.T) {
		if os.Chmod(path, 0644) != nil {
			t.Fatal("fixture mode")
		}
		if got, err := LoadDaemonConfig(ctx, path); err == nil || got != nil {
			t.Fatal("public config accepted")
		}
		if os.Chmod(path, 0600) != nil {
			t.Fatal("restore fixture mode")
		}
		link := filepath.Join(directory, "link.json")
		if os.Symlink(path, link) != nil {
			t.Fatal("fixture symlink")
		}
		if got, err := LoadDaemonConfig(ctx, link); err == nil || got != nil {
			t.Fatal("symlink config accepted")
		}
		if os.Remove(link) != nil {
			t.Fatal("fixture symlink cleanup")
		}
		if os.Link(path, link) != nil {
			t.Fatal("fixture hardlink")
		}
		if got, err := LoadDaemonConfig(ctx, path); err == nil || got != nil {
			t.Fatal("multiply linked config accepted")
		}
		if os.Remove(link) != nil {
			t.Fatal("fixture hardlink cleanup")
		}
	})
	t.Run("root-config-pin-refusal", func(t *testing.T) {
		bad := *loaded
		first := "0"
		if bad.RunnerSHA256[0] == '0' {
			first = "1"
		}
		bad.RunnerSHA256 = first + bad.RunnerSHA256[1:]
		owner, err := OpenDaemon(ctx, bad)
		if owner != nil {
			t.Cleanup(func() {
				if owner.Close(context.Background()) != nil {
					t.Error("refused owner retained")
				}
			})
		}
		if err == nil || owner == nil || owner.Close(ctx) != nil {
			t.Fatal("incorrect pin admitted or partial owner lost")
		}
		enable := "/tmp/provenance-version-pin-fixture-enabled"
		marker := "/tmp/provenance-unexpected-version-invocation"
		file, err := os.OpenFile(enable, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			t.Fatal("version canary setup")
		}
		if file.Close() != nil {
			t.Fatal("version canary file")
		}
		t.Cleanup(func() {
			if os.Remove(enable) != nil {
				t.Error("version canary setup retained")
			}
		})
		probe := filepath.Join(socket, "client")
		command := exec.CommandContext(ctx, probe, "--version")
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		if command.Run() != nil {
			t.Fatal("version canary did not run")
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatal("version canary did not observe invocation")
		}
		if os.Remove(marker) != nil {
			t.Fatal("clear exact canary marker")
		}
		bad = *loaded
		bad.SandboxPath = probe
		refused, err := OpenDaemon(ctx, bad)
		if refused != nil {
			t.Cleanup(func() {
				if refused.Close(context.Background()) != nil {
					t.Error("version refusal owner retained")
				}
			})
		}
		if err == nil || refused == nil || refused.Close(ctx) != nil {
			t.Fatal("wrong sandbox pin accepted")
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("wrong sandbox pin invoked version before refusal")
		}
	})
	daemon, err := OpenDaemon(ctx, *loaded)
	if daemon != nil {
		t.Cleanup(func() {
			if daemon.Close(context.Background()) != nil {
				t.Error("daemon retained")
			}
		})
	}
	if err != nil {
		t.Fatal("complete daemon provisioning", err)
	}
	return daemon
}
