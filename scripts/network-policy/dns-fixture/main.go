//go:build linux

// Trusted disposable fixture only; never a production privileged entry point.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"golang.org/x/net/dns/dnsmessage"
)

type fixtureResolver struct{}

func (fixtureResolver) Exchange(_ context.Context, raw []byte) ([]byte, error) {
	var message dnsmessage.Message
	if err := message.Unpack(raw); err != nil {
		return nil, err
	}
	message.Response = true
	header := dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: message.Questions[0].Type, Class: dnsmessage.ClassINET, TTL: 300}
	var body dnsmessage.ResourceBody = &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}
	if header.Type == dnsmessage.TypeAAAA {
		body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1111").As16()}
	}
	message.Answers = []dnsmessage.Resource{{Header: header, Body: body}}
	return message.Pack()
}

func nft(program string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "nft", "-f", "-")
	command.Stdin = strings.NewReader(program)
	if err := command.Run(); err != nil {
		return errors.New("fixture nft transaction failed")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() (result error) {
	ttl := flag.Duration("ttl", 8*time.Second, "disposable snapshot lifetime")
	flag.Parse()
	if flag.NArg() != 0 || (*ttl != 8*time.Second && *ttl != 30*time.Second) {
		return errors.New("unsupported fixture lifetime")
	}
	if os.Getuid() != 0 || os.Getenv("PROVENANCE_DISPOSABLE_NETWORK_FIXTURE") != "1" {
		return errors.New("disposable controller required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return err
	}
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return err
	}
	parent, err := os.Stat("/proc/1/ns/net")
	if err != nil {
		return err
	}
	if os.SameFile(current, parent) {
		return errors.New("dedicated fixture network namespace required")
	}
	job := "10000000-0000-4000-8000-000000000001"
	binder, err := networkpolicy.New(networkpolicy.Options{JobID: job, Mode: "allowlist", Permissions: []networkpolicy.Permission{{Hostname: "fixture.example.com", Port: 8080, Protocol: "tcp"}}, Limits: networkpolicy.Limits{Connections: 32, BytesPerSecond: 65536}, SensitiveNetworks: []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}, MaximumTTL: *ttl}, fixtureResolver{})
	if err != nil {
		return err
	}
	binding, err := binder.Resolve(context.Background(), "fixture.example.com")
	if err != nil {
		return err
	}
	rules, err := networkpolicy.CompileFirewallWithDNS(job, []networkpolicy.Binding{binding}, time.Now())
	if err != nil {
		return err
	}
	if err = nft(rules.Install()); err != nil {
		return err
	}
	defer func() {
		if err := nft(rules.Remove()); err != nil {
			result = err
		}
	}()
	var cancel context.CancelFunc
	var done chan error
	stop := func() error {
		if cancel == nil {
			return nil
		}
		cancel()
		cancel = nil
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		case <-time.After(3 * time.Second):
			return errors.New("fixture DNS did not stop")
		}
	}
	defer func() {
		if err := stop(); err != nil {
			result = err
		}
	}()
	start := func() error {
		view, err := networkpolicy.NewWorkloadDNS(job, []networkpolicy.Binding{binding}, time.Now())
		if err != nil {
			return err
		}
		tcp, err := net.Listen("tcp4", "10.0.1.1:53")
		if err != nil {
			return err
		}
		udp, err := net.ListenPacket("udp4", "10.0.1.1:53")
		if err != nil {
			_ = tcp.Close()
			return err
		}
		ctx, stopContext := context.WithCancel(context.Background())
		cancel = stopContext
		done = make(chan error, 1)
		go func() {
			done <- networkpolicy.ServeOwnedDNS(ctx, view, udp, tcp, []netip.Addr{netip.MustParseAddr("10.0.1.2")})
		}()
		return nil
	}
	if err = start(); err != nil {
		return err
	}
	report := func(phase string) error {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": phase, "expires": rules.ExpiresAt()})
	}
	if err = report("ready"); err != nil {
		return err
	}
	scanner := bufio.NewScanner(os.Stdin)
	withdrawn := false
	scanner.Buffer(make([]byte, 64), 64)
	for scanner.Scan() {
		switch scanner.Text() {
		case "refresh":
			if withdrawn {
				return errors.New("withdrawn fixture cannot refresh")
			}
			binding, err = binder.Resolve(context.Background(), "fixture.example.com")
			if err != nil {
				return err
			}
			next, err := networkpolicy.CompileFirewallWithDNS(job, []networkpolicy.Binding{binding}, time.Now())
			if err != nil {
				return err
			}
			program, err := rules.Refresh(next, time.Now())
			if err != nil {
				return err
			}
			if err = nft(program); err != nil {
				return err
			}
			if err = stop(); err != nil {
				return err
			}
			rules = next
			if err = start(); err != nil {
				return err
			}
			if err = report("refreshed"); err != nil {
				return err
			}
		case "withdraw":
			withdrawn = true
			program, err := rules.Withdraw()
			if err != nil {
				return err
			}
			if err = nft(program); err != nil {
				return err
			}
			if err = stop(); err != nil {
				return err
			}
			if err = report("withdrawn"); err != nil {
				return err
			}
		case "stop":
			return nil
		default:
			return errors.New("unknown fixture command")
		}
	}
	return scanner.Err()
}
