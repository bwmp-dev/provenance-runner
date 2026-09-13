// Command fixture-rules emits synthetic policy for disposable acceptance only.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"golang.org/x/net/dns/dnsmessage"
)

type resolver struct{}

func (resolver) Exchange(_ context.Context, raw []byte) ([]byte, error) {
	var q dnsmessage.Message
	if err := q.Unpack(raw); err != nil {
		return nil, err
	}
	q.Response = true
	h := dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: q.Questions[0].Type, Class: dnsmessage.ClassINET, TTL: 300}
	var body dnsmessage.ResourceBody = &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}
	if h.Type == dnsmessage.TypeAAAA {
		body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1111").As16()}
	}
	q.Answers = []dnsmessage.Resource{{Header: h, Body: body}}
	return q.Pack()
}

func main() {
	ttl := flag.Duration("ttl", 5*time.Minute, "synthetic binding lifetime")
	connections := flag.Uint64("connections", 2, "synthetic concurrent flow ceiling")
	refresh := flag.Bool("refresh", false, "include bounded same-grant renewal fixture")
	flag.Parse()
	job := "10000000-0000-4000-8000-000000000001"
	b, err := networkpolicy.New(networkpolicy.Options{JobID: job, Mode: "allowlist", Permissions: []networkpolicy.Permission{{Hostname: "fixture.example.com", Port: 8080, Protocol: "tcp"}, {Hostname: "fixture.example.com", Port: 8081, Protocol: "udp"}}, Limits: networkpolicy.Limits{Connections: *connections, BytesPerSecond: 65536}, SensitiveNetworks: []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}, MaximumTTL: *ttl}, resolver{})
	if err != nil {
		panic(err)
	}
	binding, err := b.Resolve(context.Background(), "fixture.example.com")
	if err != nil {
		panic(err)
	}
	rules, err := networkpolicy.CompileFirewall(job, []networkpolicy.Binding{binding}, time.Now())
	if err != nil {
		panic(err)
	}
	output := map[string]string{"install": rules.Install(), "remove": rules.Remove(), "expires": rules.ExpiresAt().Format(time.RFC3339)}
	if *refresh {
		// Advance a real second, not a forged future-issued binding, so nft's
		// whole-second absolute expiry can demonstrate a genuine renewal.
		time.Sleep(1100 * time.Millisecond)
		binding, err = b.Resolve(context.Background(), "fixture.example.com")
		if err != nil {
			panic(err)
		}
		next, err := networkpolicy.CompileFirewall(job, []networkpolicy.Binding{binding}, time.Now())
		if err != nil {
			panic(err)
		}
		output["refresh"], err = rules.Refresh(next, time.Now())
		if err != nil {
			panic(err)
		}
		output["withdraw"], err = next.Withdraw()
		if err != nil {
			panic(err)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
