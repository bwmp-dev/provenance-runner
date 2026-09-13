package networkpolicy

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type exchangeFunc func(context.Context, []byte) ([]byte, error)

func (f exchangeFunc) Exchange(ctx context.Context, q []byte) ([]byte, error) { return f(ctx, q) }

func options() Options {
	return Options{JobID: "10000000-0000-4000-8000-000000000001", Mode: "allowlist", Permissions: []Permission{{"api.example.com", 443, "tcp"}, {"api.example.com", 8443, "udp"}}, Limits: Limits{16, 1 << 20}, SensitiveNetworks: prefixes("93.184.216.0/24", "2606:4700:ffff::/48"), MaximumTTL: time.Minute}
}
func dnsName(s string) dnsmessage.Name { return dnsmessage.MustNewName(s + ".") }
func record(host, address string, ttl uint32) dnsmessage.Resource {
	ip := netip.MustParseAddr(address)
	header := dnsmessage.ResourceHeader{Name: dnsName(host), Class: dnsmessage.ClassINET, TTL: ttl}
	if ip.Is4() {
		header.Type = dnsmessage.TypeA
		return dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: ip.As4()}}
	}
	header.Type = dnsmessage.TypeAAAA
	return dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: ip.As16()}}
}
func alias(from, to string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsName(from), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.CNAMEResource{CNAME: dnsName(to)}}
}

func responder(change func(*dnsmessage.Message)) Exchange {
	return exchangeFunc(func(_ context.Context, raw []byte) ([]byte, error) {
		var q dnsmessage.Message
		if err := q.Unpack(raw); err != nil {
			return nil, err
		}
		q.Response = true
		address := "1.1.1.1"
		if q.Questions[0].Type == dnsmessage.TypeAAAA {
			address = "2606:4700:4700::1111"
		}
		q.Answers = []dnsmessage.Resource{record(strings.TrimSuffix(q.Questions[0].Name.String(), "."), address, 120)}
		if change != nil {
			change(&q)
		}
		return q.Pack()
	})
}
func binder(t *testing.T, e Exchange) *Binder {
	t.Helper()
	b, err := New(options(), e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBindingCopiesPinsAndExpires(t *testing.T) {
	o := options()
	b, err := New(o, responder(nil))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }
	o.Permissions[0].Hostname = "changed.example.com"
	o.SensitiveNetworks[0] = netip.MustParsePrefix("0.0.0.0/0")
	got, err := b.Resolve(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.JobID() != options().JobID || got.Hostname() != "api.example.com" || got.Limits() != options().Limits || !got.ExpiresAt().Equal(now.Add(time.Minute)) {
		t.Fatal("binding lost policy identity or TTL ceiling")
	}
	if !got.ValidAt(now) || got.ValidAt(now.Add(time.Minute)) || got.ValidAt(now.Add(-time.Second)) || (Binding{}).ValidAt(now) {
		t.Fatal("invalid binding lifetime")
	}
	addresses := got.Addresses()
	permissions := got.Permissions()
	addresses[0] = netip.MustParseAddr("127.0.0.1")
	permissions[0].Port = 25
	if got.Addresses()[0].String() != "1.1.1.1" || got.Permissions()[0].Port != 443 {
		t.Fatal("mutable binding output")
	}
	if _, err = b.Resolve(context.Background(), "changed.example.com"); !errors.Is(err, ErrDenied) {
		t.Fatal("input alias changed permissions")
	}
	if _, err = b.Resolve(context.Background(), "api.example.com"); err != nil {
		t.Fatal("stable refresh refused", err)
	}
}

func TestInvalidPolicyHasNoPermissiveDefaults(t *testing.T) {
	for name, change := range map[string]func(*Options){
		"missing job": func(o *Options) { o.JobID = "" }, "zero job": func(o *Options) { o.JobID = "00000000-0000-0000-0000-000000000000" },
		"missing sensitive": func(o *Options) { o.SensitiveNetworks = nil }, "unmasked sensitive": func(o *Options) { o.SensitiveNetworks = []netip.Prefix{netip.MustParsePrefix("8.8.8.8/24")} },
		"invalid prefix": func(o *Options) { o.SensitiveNetworks = []netip.Prefix{{}} }, "unknown mode": func(o *Options) { o.Mode = "" }, "unrestricted": func(o *Options) { o.Mode = "unrestricted" },
		"no permissions": func(o *Options) { o.Permissions = nil }, "too many": func(o *Options) { o.Permissions = make([]Permission, 129) },
		"zero connections": func(o *Options) { o.Limits.Connections = 0 }, "zero bandwidth": func(o *Options) { o.Limits.BytesPerSecond = 0 },
		"missing TTL": func(o *Options) { o.MaximumTTL = 0 }, "long TTL": func(o *Options) { o.MaximumTTL = 6 * time.Minute },
		"duplicate tuple": func(o *Options) { o.Permissions = append(o.Permissions, o.Permissions[0]) }, "invalid protocol": func(o *Options) { o.Permissions[0].Protocol = "icmp" },
		"none with grants": func(o *Options) { o.Mode = "none" },
	} {
		t.Run(name, func(t *testing.T) {
			o := options()
			change(&o)
			if _, err := New(o, responder(nil)); !errors.Is(err, ErrPolicy) {
				t.Fatal(err)
			}
		})
	}
	for _, port := range []uint16{0, 25, 465, 587, 53, 853} {
		o := options()
		o.Permissions[0].Port = port
		if _, err := New(o, responder(nil)); !errors.Is(err, ErrPolicy) {
			t.Fatalf("port %d admitted", port)
		}
	}
	for _, host := range []string{"", "localhost", "API.example.com", "api.example.com.", "*.example.com", "a..example.com", "-a.example.com", "a-.example.com", "1.2.3.4", "0x7f.0.0.1", "0177.0.0.1", "2130706433", "[::1]", "::ffff:127.0.0.1", "api.example.com\n", "api.example.com:443", "аpi.example.com", strings.Repeat("a", 64) + ".com"} {
		o := options()
		o.Permissions[0].Hostname = host
		if _, err := New(o, responder(nil)); !errors.Is(err, ErrPolicy) {
			t.Fatalf("hostname accepted: %q", host)
		}
	}
	if _, err := New(options(), nil); !errors.Is(err, ErrPolicy) {
		t.Fatal("missing controlled resolver")
	}
	o := options()
	o.Mode = "none"
	o.Permissions = nil
	o.Limits = Limits{}
	o.MaximumTTL = 0
	b, err := New(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Resolve(context.Background(), "api.example.com"); !errors.Is(err, ErrDenied) {
		t.Fatal("none allowed DNS")
	}
}

func TestSensitiveAddressesCannotAcquireBinding(t *testing.T) {
	denied := []string{"0.0.0.1", "10.0.0.1", "100.100.100.200", "127.0.0.1", "169.254.169.254", "172.31.255.255", "192.0.0.9", "192.0.2.1", "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "93.184.216.34", "::", "::1", "::ffff:1.1.1.1", "64:ff9b::a00:1", "64:ff9b:1::1", "100::1", "2001::1", "2001:db8::1", "2002:7f00:1::1", "3fff::1", "5f00::1", "fc00::1", "fe80::1", "ff02::1", "2606:4700:ffff::1"}
	for _, address := range denied {
		t.Run(address, func(t *testing.T) {
			b := binder(t, responder(func(m *dnsmessage.Message) {
				ip := netip.MustParseAddr(address)
				if (ip.Is4() && m.Questions[0].Type == dnsmessage.TypeA) || (!ip.Is4() && m.Questions[0].Type == dnsmessage.TypeAAAA) {
					m.Answers = append(m.Answers, record("api.example.com", address, 60))
				}
			}))
			if _, err := b.Resolve(context.Background(), "api.example.com"); !errors.Is(err, ErrDenied) {
				t.Fatalf("mixed answer admitted: %v", err)
			}
		})
	}
}

func TestBothFamiliesRequiredAndRebindingPoisonsOnlyThisJob(t *testing.T) {
	changed := false
	var calls atomic.Int32
	e := responder(func(m *dnsmessage.Message) {
		calls.Add(1)
		if changed && m.Questions[0].Type == dnsmessage.TypeA {
			m.Answers = []dnsmessage.Resource{record("api.example.com", "8.8.8.8", 60)}
		}
	})
	b := binder(t, e)
	if _, err := b.Resolve(context.Background(), "api.example.com"); err != nil {
		t.Fatal(err)
	}
	changed = true
	if _, err := b.Resolve(context.Background(), "api.example.com"); !errors.Is(err, ErrRebinding) {
		t.Fatal(err)
	}
	changed = false
	before := calls.Load()
	if _, err := b.Resolve(context.Background(), "api.example.com"); !errors.Is(err, ErrRebinding) || calls.Load() != before {
		t.Fatal("poisoned binding performed DNS")
	}
	changed = true
	o := options()
	o.JobID = "10000000-0000-4000-8000-000000000002"
	other, err := New(o, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Resolve(context.Background(), "api.example.com"); err != nil {
		t.Fatal("job pins leaked", err)
	}
	partial := binder(t, exchangeFunc(func(ctx context.Context, q []byte) ([]byte, error) {
		var m dnsmessage.Message
		_ = m.Unpack(q)
		if m.Questions[0].Type == dnsmessage.TypeAAAA {
			return nil, errors.New("private resolver diagnostic")
		}
		return responder(nil).Exchange(ctx, q)
	}))
	if got, err := partial.Resolve(context.Background(), "api.example.com"); !errors.Is(err, ErrDNS) || got.ValidAt(time.Now()) || strings.Contains(err.Error(), "private") {
		t.Fatal("partial family or raw error escaped", err)
	}
}

func TestMalformedDNSCannotBind(t *testing.T) {
	for name, change := range map[string]func(*dnsmessage.Message){
		"ID": func(m *dnsmessage.Message) { m.ID++ }, "query": func(m *dnsmessage.Message) { m.Response = false }, "opcode": func(m *dnsmessage.Message) { m.OpCode = 1 }, "truncated": func(m *dnsmessage.Message) { m.Truncated = true }, "rcode": func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError },
		"question": func(m *dnsmessage.Message) { m.Questions[0].Name = dnsName("other.example.com") }, "question class": func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassCHAOS }, "extra question": func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) },
		"zero TTL": func(m *dnsmessage.Message) { m.Answers[0].Header.TTL = 0 }, "class": func(m *dnsmessage.Message) { m.Answers[0].Header.Class = dnsmessage.ClassCHAOS }, "unrelated": func(m *dnsmessage.Message) { m.Answers[0].Header.Name = dnsName("other.example.com") },
		"no addresses": func(m *dnsmessage.Message) { m.Answers = nil }, "CNAME loop": func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{alias("api.example.com", "api.example.com", 60)}
		}, "CNAME dangling": func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{alias("api.example.com", "cdn.example.com", 60)}
		},
		"CNAME duplicate": func(m *dnsmessage.Message) {
			m.Answers = append(m.Answers, alias("api.example.com", "cdn.example.com", 60))
		}, "many answers": func(m *dnsmessage.Message) {
			for len(m.Answers) < 65 {
				m.Answers = append(m.Answers, m.Answers[0])
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := binder(t, responder(change))
			if _, err := b.Resolve(context.Background(), "api.example.com"); !errors.Is(err, ErrDNS) {
				t.Fatal(err)
			}
		})
	}
	for _, raw := range [][]byte{nil, make([]byte, maxDNSBytes+1), {0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255}} {
		b := binder(t, exchangeFunc(func(context.Context, []byte) ([]byte, error) { return raw, nil }))
		if _, err := b.Resolve(context.Background(), "api.example.com"); !errors.Is(err, ErrDNS) {
			t.Fatal(err)
		}
	}
	b := binder(t, exchangeFunc(func(ctx context.Context, q []byte) ([]byte, error) {
		r, err := responder(nil).Exchange(ctx, q)
		return append(r, 0), err
	}))
	if _, err := b.Resolve(context.Background(), "api.example.com"); !errors.Is(err, ErrDNS) {
		t.Fatal("trailing DNS bytes accepted")
	}
}

func TestCNAMEExpiryAndConcurrentResolution(t *testing.T) {
	e := responder(func(m *dnsmessage.Message) {
		m.Answers[0].Header.Name = dnsName("cdn.example.com")
		m.Answers = append(m.Answers, alias("api.example.com", "cdn.example.com", 2))
	})
	b := binder(t, e)
	now := time.Now()
	b.now = func() time.Time { return now }
	got, err := b.Resolve(context.Background(), "api.example.com")
	if err != nil || !got.ExpiresAt().Equal(now.Add(2*time.Second)) {
		t.Fatalf("CNAME minimum TTL: %v", err)
	}
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			v, err := b.Resolve(context.Background(), "api.example.com")
			if err != nil || !reflect.DeepEqual(v.Addresses(), got.Addresses()) {
				t.Errorf("concurrent pin: %v", err)
			}
		}()
	}
	group.Wait()
	late := binder(t, e)
	ticks := 0
	late.now = func() time.Time {
		ticks++
		if ticks == 1 {
			return now
		}
		return now.Add(3 * time.Second)
	}
	if _, err := late.Resolve(context.Background(), "api.example.com"); !errors.Is(err, ErrExpired) {
		t.Fatal("expired resolution produced binding", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Resolve(ctx, "api.example.com"); !errors.Is(err, ErrDNS) {
		t.Fatal("cancelled resolution admitted", err)
	}
}
