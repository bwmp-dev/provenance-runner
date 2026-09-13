package networkpolicy

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func workloadDNSFixture(t *testing.T) (*WorkloadDNS, Binding, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 13, 0, 0, 0, 123000000, time.UTC)
	b := binder(t, responder(nil))
	b.now = func() time.Time { return now }
	binding, err := b.Resolve(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	view, err := NewWorkloadDNS(options().JobID, []Binding{binding}, now)
	if err != nil {
		t.Fatal(err)
	}
	return view, binding, now
}

func workloadQuery(t *testing.T, host string, family dnsmessage.Type) []byte {
	t.Helper()
	raw, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsName(host), Type: family, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWorkloadDNSEmptyEDNSOnly(t *testing.T) {
	view, _, now := workloadDNSFixture(t)
	for _, test := range []struct {
		name    string
		change  func(*dnsmessage.Message)
		allowed bool
	}{
		{"standard1232", func(*dnsmessage.Message) {}, true},
		{"minimum512", func(m *dnsmessage.Message) { m.Additionals[0].Header.Class = 512 }, true},
		{"maximum4096", func(m *dnsmessage.Message) { m.Additionals[0].Header.Class = 4096 }, true},
		{"tooSmall", func(m *dnsmessage.Message) { m.Additionals[0].Header.Class = 511 }, false},
		{"tooLarge", func(m *dnsmessage.Message) { m.Additionals[0].Header.Class = 4097 }, false},
		{"flags", func(m *dnsmessage.Message) { m.Additionals[0].Header.TTL = 32768 }, false},
		{"version", func(m *dnsmessage.Message) { m.Additionals[0].Header.TTL = 65536 }, false},
		{"extendedCode", func(m *dnsmessage.Message) { m.Additionals[0].Header.TTL = 1 << 24 }, false},
		{"nonRoot", func(m *dnsmessage.Message) { m.Additionals[0].Header.Name = dnsName("api.example.com") }, false},
		{"option", func(m *dnsmessage.Message) {
			m.Additionals[0].Body = &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 8, Data: []byte{1}}}}
		}, false},
		{"duplicate", func(m *dnsmessage.Message) { m.Additionals = append(m.Additionals, m.Additionals[0]) }, false},
		{"address", func(m *dnsmessage.Message) {
			m.Additionals[0].Header.Type = dnsmessage.TypeA
			m.Additionals[0].Body = &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var query dnsmessage.Message
			if err := query.Unpack(workloadQuery(t, "api.example.com", dnsmessage.TypeA)); err != nil {
				t.Fatal(err)
			}
			query.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232}, Body: &dnsmessage.OPTResource{}}}
			test.change(&query)
			raw, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			for _, tcp := range []bool{false, true} {
				answer, err := view.Answer(raw, tcp, now)
				if (err == nil) != test.allowed {
					t.Fatalf("allowed=%v err=%v", test.allowed, err)
				}
				if test.allowed {
					var response dnsmessage.Message
					if response.Unpack(answer) != nil || len(answer) > 512 || len(response.Answers) != 1 || len(response.Additionals) != 0 {
						t.Fatal("EDNS expanded response authority")
					}
				}
			}
		})
	}
}

func TestWorkloadDNSBoundSnapshotAndWithdrawal(t *testing.T) {
	view, binding, now := workloadDNSFixture(t)
	for _, family := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		raw, err := view.Answer(workloadQuery(t, "API.example.com", family), false, now)
		if err != nil {
			t.Fatal(err)
		}
		var response dnsmessage.Message
		if response.Unpack(raw) != nil || response.ID != 42 || !response.Response || response.RecursionAvailable || response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 1 || response.Answers[0].Header.TTL != 59 {
			t.Fatal("unbound answer or extended kernel TTL", response)
		}
	}
	for _, host := range []string{"unlisted.example.com", "alias.example.com", "127.0.0.1", "0x10000000000000000000000.0x7f"} {
		raw, err := view.Answer(workloadQuery(t, host, dnsmessage.TypeA), false, now)
		if err != nil {
			t.Fatal(err)
		}
		var response dnsmessage.Message
		_ = response.Unpack(raw)
		if response.RCode != dnsmessage.RCodeRefused || len(response.Answers) != 0 {
			t.Fatal("ungranted name answered")
		}
	}
	for _, when := range []time.Time{now.Add(-time.Nanosecond), time.Unix(binding.ExpiresAt().Unix(), 0), binding.ExpiresAt()} {
		raw, err := view.Answer(workloadQuery(t, binding.Hostname(), dnsmessage.TypeA), false, when)
		if err != nil {
			t.Fatal(err)
		}
		var response dnsmessage.Message
		_ = response.Unpack(raw)
		if response.RCode != dnsmessage.RCodeServerFailure || len(response.Answers) != 0 {
			t.Fatal("inactive lifetime answered")
		}
	}
	view.Withdraw()
	view.Withdraw()
	raw, err := view.Answer(workloadQuery(t, binding.Hostname(), dnsmessage.TypeA), false, now)
	if err != nil {
		t.Fatal(err)
	}
	var response dnsmessage.Message
	_ = response.Unpack(raw)
	if response.RCode != dnsmessage.RCodeServerFailure || len(response.Answers) != 0 {
		t.Fatal("withdrawal resumed")
	}
}

func TestWorkloadDNSHostileEnvelopeAndBoundedTruncation(t *testing.T) {
	view, binding, now := workloadDNSFixture(t)
	valid := workloadQuery(t, binding.Hostname(), dnsmessage.TypeA)
	for _, raw := range [][]byte{nil, {}, valid[:11], append(append([]byte{}, valid...), 0), make([]byte, 513)} {
		if _, err := view.Answer(raw, false, now); err == nil {
			t.Fatal("malformed envelope accepted")
		}
	}
	for _, mutate := range []func(*dnsmessage.Message){
		func(q *dnsmessage.Message) { q.Response = true },
		func(q *dnsmessage.Message) { q.OpCode = 1 },
		func(q *dnsmessage.Message) { q.Truncated = true },
		func(q *dnsmessage.Message) { q.Questions = append(q.Questions, q.Questions[0]) },
		func(q *dnsmessage.Message) {
			q.Answers = []dnsmessage.Resource{record(binding.Hostname(), "127.0.0.1", 60)}
		},
	} {
		var query dnsmessage.Message
		_ = query.Unpack(valid)
		mutate(&query)
		raw, err := query.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = view.Answer(raw, true, now); err == nil {
			t.Fatal("unsupported DNS envelope accepted")
		}
	}
	// A view must not alias its caller's address slice, even in trusted code.
	binding.addresses = []netip.Addr{}
	for i := 1; i <= 40; i++ {
		binding.addresses = append(binding.addresses, netip.AddrFrom4([4]byte{1, 1, 1, byte(i)}))
	}
	large, err := NewWorkloadDNS(binding.JobID(), []Binding{binding}, now)
	if err != nil {
		t.Fatal(err)
	}
	binding.addresses[0] = netip.MustParseAddr("127.0.0.1")
	for _, tcp := range []bool{false, true} {
		raw, err := large.Answer(valid, tcp, now)
		if err != nil {
			t.Fatal(err)
		}
		var response dnsmessage.Message
		_ = response.Unpack(raw)
		if !tcp && (len(raw) > 512 || !response.Truncated || len(response.Answers) != 0) {
			t.Fatal("UDP amplification bound")
		}
		if tcp && (len(raw) > 4096 || response.Truncated || len(response.Answers) != 40 || response.Answers[0].Body.(*dnsmessage.AResource).A == [4]byte{127, 0, 0, 1}) {
			t.Fatal("TCP bound or aliased view")
		}
	}
}

func TestWorkloadDNSConcurrentWithdrawal(t *testing.T) {
	view, binding, now := workloadDNSFixture(t)
	raw := workloadQuery(t, binding.Hostname(), dnsmessage.TypeA)
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 50 {
				_, _ = view.Answer(raw, false, now)
			}
		}()
	}
	view.Withdraw()
	wait.Wait()
	answer, err := view.Answer(raw, false, now)
	if err != nil {
		t.Fatal(err)
	}
	var response dnsmessage.Message
	_ = response.Unpack(answer)
	if len(response.Answers) != 0 {
		t.Fatal("withdrawn view answered")
	}
}

func FuzzWorkloadDNSBoundedWire(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false)
	f.Fuzz(func(t *testing.T, raw []byte, tcp bool) {
		if len(raw) > 1024 {
			t.Skip()
		}
		view, _, now := workloadDNSFixture(t)
		answer, err := view.Answer(raw, tcp, now)
		if err == nil {
			var response dnsmessage.Message
			if len(answer) > 4096 || (!tcp && len(answer) > 512) || response.Unpack(answer) != nil || !response.Response {
				t.Fatal("unbounded or malformed response")
			}
		}
	})
}
