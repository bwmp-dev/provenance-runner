//go:build linux

// Trusted fixture only: creates a caller-mapped user/network namespace and runs
// the pinned Sentry after the outer disposable controller has connected its veth.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func main() {
	if measuredObservationClient != nil && measuredObservationClient() {
		return
	}
	if measuredControlClient != nil && measuredControlClient() {
		return
	}
	if len(os.Args) > 2 && strings.HasPrefix(os.Args[1], "-Xms") {
		paperPreparationFixture()
		return
	}
	if len(os.Args) != 2 {
		panic("fixture mode required")
	}
	switch os.Args[1] {
	case "parent":
		if os.Getuid() != 0 || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
			panic("disposable root controller required")
		}
		if err := syscall.Setgroups([]int{}); err != nil {
			panic(err)
		}
		child := exec.Command("/usr/local/bin/network-sentry-fixture", "child")
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		child.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
			UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 65532, Size: 1}, {ContainerID: 65534, HostID: 65533, Size: 1}},
			GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 65532, Size: 1}, {ContainerID: 65534, HostID: 65533, Size: 1}},
			Credential:                 &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true},
			GidMappingsEnableSetgroups: false, Pdeathsig: syscall.SIGKILL,
		}
		if err := child.Start(); err != nil {
			panic(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]int{"namespacePID": child.Process.Pid}); err != nil {
			panic(err)
		}
		if err := child.Wait(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "child":
		if os.Getuid() != 0 {
			panic("mapped namespace root required")
		}
		var barrier [1]byte
		if _, err := io.ReadFull(os.Stdin, barrier[:]); err != nil || barrier[0] != 's' {
			panic("controller barrier required")
		}
		args := []string{"runsc", "--root=/fixture/state", "--rootless=false", "--ignore-cgroups=true", "--network=sandbox", "--platform=systrap", "--overlay2=none", "--directfs=false", "--file-access=exclusive", "--file-access-mounts=exclusive", "--gofer-network-namespace=new", "--net-raw=false", "--host-uds=none", "--host-fifo=none", "--allow-suid=false", "--character-device-policy=emulated-only", "run", "--bundle=/fixture/bundle", "network-fixture"}
		if err := syscall.Exec("/opt/gvisor/runsc", args, os.Environ()); err != nil {
			panic(err)
		}
	case "dns-probe":
		if os.Getuid() != 65532 || os.Geteuid() != 65532 {
			panic("non-root guest required")
		}
		result := map[string]bool{"nonRootGuest": true}
		for _, transport := range []string{"udp", "tcp"} {
			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, transport, "10.0.1.1:53")
			}}
			for _, family := range []string{"ip4", "ip6"} {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				addresses, err := resolver.LookupIP(ctx, family, "fixture.example.com.")
				cancel()
				want := "1.1.1.1"
				if family == "ip6" {
					want = "2606:4700:4700::1111"
				}
				if err != nil || len(addresses) != 1 || addresses[0].String() != want {
					panic("Sentry DNS binding failed: " + transport + family)
				}
				result[transport+family] = true
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			addresses, err := resolver.LookupIP(ctx, "ip4", "unlisted.example.com.")
			cancel()
			if err == nil || len(addresses) != 0 {
				panic("Sentry DNS unlisted hostname answered")
			}
			result[transport+"UnlistedDenied"] = true
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			panic(err)
		}
	case "dns-lifecycle":
		if os.Getuid() != 65532 || os.Geteuid() != 65532 {
			panic("non-root guest required")
		}
		probe := func(allowed bool) {
			for _, transport := range []string{"udp", "tcp"} {
				resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, transport, "10.0.1.1:53")
				}}
				for _, family := range []string{"ip4", "ip6"} {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					addresses, err := resolver.LookupIP(ctx, family, "fixture.example.com.")
					cancel()
					want := "1.1.1.1"
					if family == "ip6" {
						want = "2606:4700:4700::1111"
					}
					if allowed {
						if err != nil || len(addresses) != 1 || addresses[0].String() != want {
							panic("live Sentry DNS binding failed")
						}
					} else if err == nil || len(addresses) != 0 {
						panic("withdrawn Sentry DNS remained available")
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				addresses, err := resolver.LookupIP(ctx, "ip4", "unlisted.example.com.")
				cancel()
				if err == nil || len(addresses) != 0 {
					panic("unlisted Sentry DNS answered")
				}
			}
		}
		report := func(phase string) {
			if json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": phase, "nonRootGuest": true}) != nil {
				panic("report failed")
			}
		}
		probe(true)
		report("ready")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 64), 64)
		if !scanner.Scan() || scanner.Text() != "refresh" {
			panic("refresh barrier missing")
		}
		probe(true)
		report("refreshed")
		if !scanner.Scan() || scanner.Text() != "withdraw" {
			panic("withdraw barrier missing")
		}
		probe(false)
		report("withdrawn")
	case "probe", "probe-lifecycle", "probe-confined", "probe-confined-lifecycle", "probe-confined-dns", "probe-confined-dns-lifecycle":
		if os.Getuid() != 65532 || os.Geteuid() != 65532 {
			panic("non-root guest required")
		}
		result := map[string]bool{"nonRootGuest": true}
		if strings.HasPrefix(os.Args[1], "probe-confined") {
			probeStorage(result)
		}
		for _, test := range []struct {
			name, network, address string
			allowed                bool
		}{
			{"tcp4", "tcp", "1.1.1.1:8080", true},
			{"tcp6", "tcp", "[2606:4700:4700::1111]:8080", true},
			{"udp4", "udp", "1.1.1.1:8081", true},
			{"udp6", "udp", "[2606:4700:4700::1111]:8081", true},
			{"unbound4", "tcp", "1.0.0.1:8080", false},
			{"unbound6", "tcp", "[2606:4700:4700::1001]:8080", false},
			{"metadata", "tcp", "169.254.169.254:8080", false},
			{"wrongPort", "tcp", "1.1.1.1:8082", false},
			{"wrongProtocol", "udp", "1.1.1.1:8080", false},
		} {
			ok := func() bool {
				conn, err := net.DialTimeout(test.network, test.address, 750*time.Millisecond)
				if err != nil {
					return false
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(750 * time.Millisecond))
				if _, err := conn.Write([]byte("sentry-fixture")); err != nil {
					return false
				}
				var data [14]byte
				_, err = io.ReadFull(conn, data[:])
				return err == nil && string(data[:]) == "sentry-fixture"
			}()
			if ok != test.allowed {
				panic("Sentry packet boundary failed: " + test.name)
			}
			result[test.name] = true
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			panic(err)
		}
		if strings.Contains(os.Args[1], "-dns") {
			probeOwnedDNS()
		}
		if strings.HasSuffix(os.Args[1], "-lifecycle") {
			packetLifecycle()
		}
	default:
		panic("unknown fixture mode")
	}
}

// The standalone Docker build compiles only this standard-library entry point.
// Module builds register additional trusted control fixtures in separate files.
var measuredControlClient func() bool
var measuredObservationClient func() bool

// Synthetic Java stand-in, executed only by the measured disposable fixture.
// No Paper/plugin compatibility claim is made by this helper.
func paperPreparationFixture() {
	if os.Getuid() != 65532 || os.Getgid() != 65532 {
		panic("non-root guest required")
	}
	secret, secretErr := os.ReadFile("/run/provenance/test-secrets/license")
	if secretErr != nil || string(secret) != "synthetic-late-guest-secret" {
		panic("late secret mount unavailable")
	}
	clear(secret)
	if os.WriteFile("/run/provenance/test-secrets/license", []byte("changed"), 0600) == nil || os.WriteFile("/run/provenance/test-secrets/new", []byte("changed"), 0600) == nil || os.Chmod("/run/provenance/test-secrets", 0700) == nil {
		panic("mutable secret mount")
	}
	entries, secretErr := os.ReadDir("/run/provenance/test-secrets")
	if secretErr != nil || len(entries) != 1 || entries[0].Name() != "license" {
		panic("unexpected secret mount entries")
	}
	for name, want := range map[string]string{"paper.jar": "synthetic paper", "plugins/target.jar": "synthetic target", "plugins/provenance-probe.jar": "synthetic probe", "cache/patched.jar": "synthetic prepared"} {
		raw, err := os.ReadFile(name)
		if err != nil || string(raw) != want {
			panic("guest input role mismatch")
		}
	}
	if _, err := os.Stat(os.Getenv("JAVA_HOME") + "/bin/java"); err != nil {
		panic("guest Java layout")
	}
	if err := os.WriteFile("/inputs/target.jar", []byte("changed"), 0600); err == nil {
		panic("writable input mount")
	}
	if err := os.WriteFile("/tmp/provenance-probe-events.ndjson", []byte("{\"syntheticPaperEvent\":true}\n"), 0600); err != nil {
		panic("guest event channel")
	}
	fmt.Fprintln(os.Stdout, "synthetic Paper guest prepared")
	fmt.Fprintln(os.Stderr, "synthetic Paper guest stderr")
	time.Sleep(500 * time.Millisecond)
}

func probeOwnedDNS() {
	result := map[string]bool{}
	contents, err := os.ReadFile("/etc/resolv.conf")
	if err != nil || string(contents) != "nameserver 10.0.1.1\noptions timeout:1 attempts:1\n" {
		panic("fixed resolver configuration missing")
	}
	if file, err := os.OpenFile("/etc/resolv.conf", os.O_WRONLY|os.O_TRUNC, 0); err == nil {
		file.Close()
		panic("resolver configuration writable")
	}
	result["resolverReadOnly"] = true
	for _, family := range []string{"ip4", "ip6"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		addresses, err := net.DefaultResolver.LookupIP(ctx, family, "fixture.example.com.")
		cancel()
		want := "1.1.1.1"
		if family == "ip6" {
			want = "2606:4700:4700::1111"
		}
		if err != nil || len(addresses) != 1 || addresses[0].String() != want {
			panic("default resolver binding failed")
		}
		result["default"+family] = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", "unlisted.example.com.")
	cancel()
	if err == nil || len(addresses) != 0 {
		panic("default resolver unlisted name answered")
	}
	result["defaultUnlistedDenied"] = true
	for _, transport := range []string{"udp", "tcp"} {
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, transport, "10.0.1.1:53")
		}}
		for _, family := range []string{"ip4", "ip6"} {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			addresses, err := resolver.LookupIP(ctx, family, "fixture.example.com.")
			cancel()
			want := "1.1.1.1"
			if family == "ip6" {
				want = "2606:4700:4700::1111"
			}
			if err != nil || len(addresses) != 1 || addresses[0].String() != want {
				panic("owned DNS binding failed")
			}
			result[transport+family] = true
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		addresses, err := resolver.LookupIP(ctx, "ip4", "unlisted.example.com.")
		cancel()
		if err == nil || len(addresses) != 0 {
			panic("owned DNS unlisted name answered")
		}
		result[transport+"UnlistedDenied"] = true
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		panic("owned DNS report failed")
	}
}

// Synthetic guest only. The measured fixture grants exactly two MiB of writable
// storage, split evenly between two private tmpfs mounts. No host data is used.
func probeStorage(result map[string]bool) {
	if cwd, err := os.Getwd(); err != nil || cwd != "/workspace" {
		panic("private working directory missing")
	}
	result["privateWorkingDirectory"] = true
	for _, test := range []struct{ path, name string }{{"/workspace/quota", "workspaceQuota"}, {"/tmp/quota", "temporaryQuota"}} {
		file, err := os.OpenFile(test.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			panic("private writable mount missing")
		}
		var chunk [4096]byte
		total := 0
		for total <= 1<<20 {
			n, writeErr := file.Write(chunk[:])
			total += n
			if writeErr != nil {
				err = writeErr
				break
			}
			if n == 0 {
				panic("quota write made no progress")
			}
		}
		if file.Close() != nil || total == 0 || total > 1<<20 || !errors.Is(err, syscall.ENOSPC) || os.Remove(test.path) != nil {
			panic("private tmpfs quota not enforced")
		}
		result[test.name] = true
	}
	if !readOnlyGuestMount("/") || os.WriteFile("/forbidden", []byte("synthetic"), 0600) == nil {
		panic("root is not read-only")
	}
	result["rootReadOnly"] = true
	if raw, err := os.ReadFile("/inputs/sample"); err != nil || string(raw) != "synthetic-input" {
		panic("read-only fixture input missing")
	}
	if !readOnlyGuestMount("/inputs") || os.WriteFile("/inputs/sample", []byte("changed"), 0600) == nil {
		panic("inputs are not read-only")
	}
	result["inputsReadOnly"] = true
}

func readOnlyGuestMount(path string) bool {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(raw) > 65536 {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[4] == path {
			return strings.Contains(","+fields[5]+",", ",ro,")
		}
	}
	return false
}

// Keep the same Sentry and four sockets alive across the controller's atomic
// refresh and withdrawal. These are real guest packets, not restored host links.
func packetLifecycle() {
	var connections []net.Conn
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	endpoints := []struct{ network, address string }{
		{"tcp", "1.1.1.1:8080"}, {"tcp", "[2606:4700:4700::1111]:8080"},
		{"udp", "1.1.1.1:8081"}, {"udp", "[2606:4700:4700::1111]:8081"},
	}
	echo := func(connection net.Conn) bool {
		if connection.SetDeadline(time.Now().Add(750*time.Millisecond)) != nil {
			return false
		}
		if _, err := connection.Write([]byte("live")); err != nil {
			return false
		}
		var answer [4]byte
		_, err := io.ReadFull(connection, answer[:])
		return err == nil && string(answer[:]) == "live"
	}
	for _, endpoint := range endpoints {
		connection, err := net.DialTimeout(endpoint.network, endpoint.address, time.Second)
		if err != nil {
			panic("persistent guest connection unavailable")
		}
		connections = append(connections, connection)
		if !echo(connection) {
			panic("persistent guest connection failed before renewal")
		}
	}
	report := func(phase string) {
		if json.NewEncoder(os.Stdout).Encode(map[string]string{"phase": phase}) != nil {
			panic("packet report failed")
		}
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64), 64)
	report("flows-ready")
	if !scanner.Scan() || scanner.Text() != "refresh" {
		panic("packet refresh barrier missing")
	}
	for _, connection := range connections {
		if !echo(connection) {
			panic("renewal broke persistent guest flow")
		}
	}
	report("flows-refreshed")
	if !scanner.Scan() || scanner.Text() != "withdraw" {
		panic("packet withdrawal barrier missing")
	}
	for _, connection := range connections {
		if echo(connection) {
			panic("withdrawal retained established guest flow")
		}
	}
	for _, endpoint := range endpoints {
		connection, err := net.DialTimeout(endpoint.network, endpoint.address, 750*time.Millisecond)
		if err == nil {
			allowed := echo(connection)
			_ = connection.Close()
			if allowed {
				panic("withdrawal admitted new guest flow")
			}
		}
	}
	report("flows-withdrawn")
}
