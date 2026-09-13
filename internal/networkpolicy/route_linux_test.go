//go:build linux

package networkpolicy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRetainedRouteClosedChangesAndOutputBound(t *testing.T) {
	var output routeOutput
	if _, ok := any(&output).(io.ReaderFrom); ok {
		t.Fatal("unbounded ReaderFrom bypass")
	}
	if _, err := io.Copy(&output, strings.NewReader(strings.Repeat("x", 65537))); err == nil || len(output.Bytes()) > 65536 {
		t.Fatal("route output unbounded")
	}
	var route *RetainedRoute
	if route.Apply(context.Background(), FirewallChange{}) != ErrActuation || route.Disconnect(context.Background()) != ErrActuation || route.JobID() != "" || route.Close() != nil {
		t.Fatal("nil route handling")
	}
	if r, err := NewRetainedRoute("invalid", nil, nil, RouteTools{}); r != nil || err != ErrNamespace {
		t.Fatal("invalid owner accepted")
	}
	if validRouteTool(ProtectedRouteTool{}) {
		t.Fatal("unidentified executable accepted")
	}
}

func TestRetainedRouteMappingSeparation(t *testing.T) {
	a := MappedIdentity{UID: 10, OverflowUID: 11, GID: 20, OverflowGID: 21}
	b := MappedIdentity{UID: 12, OverflowUID: 13, GID: 22, OverflowGID: 23}
	if !separateRouteMappings(a, b) {
		t.Fatal("separate identities refused")
	}
	for _, uid := range []uint32{a.UID, a.OverflowUID} {
		for _, overflow := range []bool{false, true} {
			changed := b
			if overflow {
				changed.OverflowUID = uid
			} else {
				changed.UID = uid
			}
			if separateRouteMappings(a, changed) {
				t.Fatal("overlapping user identity accepted")
			}
		}
	}
	for _, gid := range []uint32{a.GID, a.OverflowGID} {
		for _, overflow := range []bool{false, true} {
			changed := b
			if overflow {
				changed.OverflowGID = gid
			} else {
				changed.GID = gid
			}
			if separateRouteMappings(a, changed) {
				t.Fatal("overlapping group identity accepted")
			}
		}
	}
}

func TestRetainedRouteKernelActuation(t *testing.T) {
	if os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		t.Skip("explicit disposable kernel fixture required")
	}
	if os.Getuid() != 0 {
		t.Fatal("disposable root controller required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container required")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("fixture must have network=none")
	}
	if syscall.Setgroups([]int{}) != nil {
		t.Fatal("cannot drop disposable groups")
	}
	const job = "10000000-0000-4000-8000-000000000001"
	load := func(name string) ProtectedRouteTool {
		t.Helper()
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatal("fixture tool missing")
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal("fixture tool unavailable")
		}
		t.Cleanup(func() { f.Close() })
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			t.Fatal("fixture tool digest unavailable")
		}
		return ProtectedRouteTool{File: f, SHA256: [32]byte(h.Sum(nil))}
	}
	tools := RouteTools{NSenter: load("nsenter"), NFT: load("nft"), IP: load("ip")}
	holder := func(t *testing.T, uid uint32) (*ChildNamespaces, *exec.Cmd, *os.File) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMappedChildNamespaceProcess$")
		cmd.Env = []string{"PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1", "PROVENANCE_NAMESPACE_TEST_CHILD=holder"}
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNET | unix.CLONE_NEWNS,
			UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(uid), Size: 1}, {ContainerID: 65534, HostID: int(uid + 1), Size: 1}},
			GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(uid), Size: 1}, {ContainerID: 65534, HostID: int(uid + 1), Size: 1}},
			GidMappingsEnableSetgroups: false, Credential: &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL}
		if cmd.Start() != nil {
			cancel()
			t.Fatal("route child unavailable")
		}
		t.Cleanup(func() { input.Close(); cancel(); _ = cmd.Wait() })
		line, err := bufio.NewReaderSize(output, 256).ReadString('\n')
		if err != nil || line != "ready\n" {
			t.Fatal("route child not ready")
		}
		identity, err := RetainMappedChild(job, cmd.Process, MappedIdentity{UID: uid, GID: uid, OverflowUID: uid + 1, OverflowGID: uid + 1})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { identity.Close() })
		namespace, err := identity.NetworkForJob(job)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { namespace.Close() })
		return identity, cmd, namespace
	}
	for _, childExit := range []bool{false, true} {
		t.Run(map[bool]string{false: "install-renew-withdraw", true: "cleanup-after-child-exit"}[childExit], func(t *testing.T) {
			router, routerProcess, routerFD := holder(t, 65530)
			workload, workloadProcess, _ := holder(t, 65532)
			selected := tools
			copyPath := filepath.Join(t.TempDir(), "retained-ip")
			copyFile, err := os.OpenFile(copyPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0755)
			if err != nil {
				t.Fatal("owned tool fixture unavailable")
			}
			t.Cleanup(func() { copyFile.Close() })
			stat, err := tools.IP.File.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(copyFile, io.NewSectionReader(tools.IP.File, 0, stat.Size())); err != nil {
				t.Fatal("owned tool fixture copy failed")
			}
			if validRouteTool(ProtectedRouteTool{File: copyFile, SHA256: tools.IP.SHA256}) {
				t.Fatal("writable executable descriptor accepted")
			}
			if copyFile.Close() != nil {
				t.Fatal("owned writer close failed")
			}
			copyFile, err = os.Open(copyPath)
			if err != nil {
				t.Fatal("owned read-only executable unavailable")
			}
			selected.IP = ProtectedRouteTool{File: copyFile, SHA256: tools.IP.SHA256}
			bad := selected
			bad.NFT.SHA256[0] ^= 1
			if r, err := NewRetainedRoute(job, router, workload, bad); r != nil || err != ErrActuation {
				t.Fatal("wrong tool identity accepted")
			}
			route, err := NewRetainedRoute(job, router, workload, selected)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { route.Close() })
			// Replace only the owned temporary pathname. Every operation below
			// must still execute the retained original inode, including cleanup.
			if os.Remove(copyPath) != nil || os.WriteFile(copyPath, []byte("#!/bin/sh\nexit 99\n"), 0755) != nil {
				t.Fatal("owned replacement fixture unavailable")
			}
			// No ambient routes are configured. Setup changes only this fresh
			// retained child and the two explicitly owned disposable peers.
			setup := func(args ...string) {
				t.Helper()
				if _, err := route.execute(context.Background(), route.tools.IP, "", args...); err != nil {
					t.Fatal("owned link fixture setup failed")
				}
			}
			setup("link", "add", "job0", "type", "veth", "peer", "name", "jobpeer")
			setup("link", "set", "jobpeer", "netns", strconv.Itoa(workloadProcess.Process.Pid))
			setup("link", "add", "wan0", "type", "veth", "peer", "name", "wanpeer")
			setup("link", "set", "wanpeer", "netns", strconv.Itoa(workloadProcess.Process.Pid))
			setup("link", "set", "job0", "up")
			setup("link", "set", "wan0", "up")
			binding := liveRouteBinding(t)
			// A mismatched session must refuse before any actuation or cleanup.
			wrong := binding
			wrong.job = "20000000-0000-4000-8000-000000000001"
			if session, err := StartRoute(context.Background(), wrong.job, []Binding{wrong}, route); session != nil || err != ErrPolicy {
				t.Fatal("wrong job touched owned route")
			}
			session, err := StartRoute(context.Background(), job, []Binding{binding}, route)
			if err != nil {
				t.Fatal("owned installation failed", err)
			}
			t.Cleanup(func() {
				if err := session.Close(); err != nil {
					t.Error(err)
				}
			})
			if _, err := session.DNS(); err != nil {
				t.Fatal("installed snapshot unavailable")
			}
			var tables struct {
				Items []map[string]json.RawMessage `json:"nftables"`
			}
			raw, err := route.execute(context.Background(), route.tools.NFT, "", "-j", "list", "tables")
			if err != nil || json.Unmarshal(raw, &tables) != nil {
				t.Fatal("owned firewall unreadable")
			}
			count := 0
			for _, entry := range tables.Items {
				if _, ok := entry["table"]; ok {
					count++
				}
			}
			if count != 1 {
				t.Fatal("owned table missing")
			}
			if err := route.Apply(context.Background(), FirewallChange{}); err != ErrActuation {
				t.Fatal("zero privileged change accepted")
			}
			// The controller network remains unchanged; nft only ran through the
			// retained child descriptor, including both cleanup paths below.
			ambient, err := exec.Command("nft", "-j", "list", "tables").Output()
			if err != nil || strings.Contains(string(ambient), "pv_") {
				t.Fatal("controller namespace was modified")
			}
			binding.expires = binding.expires.Add(time.Second)
			if err := session.Refresh(context.Background(), []Binding{binding}); err != nil {
				t.Fatal("owned renewal failed", err)
			}
			if childExit {
				if routerProcess.Process.Kill() != nil || routerProcess.Wait() == nil {
					t.Fatal("owned router child did not exit")
				}
				if router.Validate(job) != ErrNamespace {
					t.Fatal("dead router retained admission")
				}
			}
			if err := session.Close(); err != nil {
				t.Fatal("owned cleanup failed", err)
			}
			raw, err = route.execute(context.Background(), route.tools.IP, "", "-j", "link", "show", "job0")
			if err != nil || strings.Contains(string(raw), `"UP"`) {
				t.Fatal("owned route still connected")
			}
			raw, err = route.execute(context.Background(), route.tools.NFT, "", "-j", "list", "tables")
			if err != nil || strings.Contains(string(raw), "pv_") {
				t.Fatal("owned table remains")
			}
			if err := session.Refresh(context.Background(), []Binding{binding}); err != ErrExpired {
				t.Fatal("withdrawn native route resumed")
			}
			if !sameNamespace(routerFD, route.network, unix.CLONE_NEWNET) {
				t.Fatal("retained object changed")
			}
		})
	}
}
