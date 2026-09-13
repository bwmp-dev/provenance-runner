//go:build linux

// Trusted fixture only: creates a caller-mapped user/network namespace and runs
// the pinned Sentry after the outer disposable controller has connected its veth.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func main() {
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
	case "probe":
		if os.Getuid() != 65532 || os.Geteuid() != 65532 {
			panic("non-root guest required")
		}
		result := map[string]bool{"nonRootGuest": true}
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
	default:
		panic("unknown fixture mode")
	}
}
