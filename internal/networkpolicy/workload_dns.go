package networkpolicy

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// WorkloadDNS prepares answers solely from one job's immutable binding snapshot.
// It has no resolver or socket and cannot add or refresh grants. An actuator must
// expose it only after installing this snapshot's firewall, and call Withdraw
// before disconnect/cleanup. Construction alone proves no installed protection.
type WorkloadDNS struct {
	mu              sync.RWMutex
	bindings        map[string]Binding
	issued, expires time.Time
	withdrawn       bool
}

func NewWorkloadDNS(job string, bindings []Binding, now time.Time) (*WorkloadDNS, error) {
	firewall, err := CompileFirewall(job, bindings, now)
	if err != nil {
		return nil, err
	}
	view := &WorkloadDNS{bindings: make(map[string]Binding, len(bindings)), issued: now, expires: time.Unix(firewall.ExpiresAt().Unix(), 0)}
	for _, binding := range bindings {
		binding.addresses = binding.Addresses()
		binding.permissions = binding.Permissions()
		view.bindings[binding.hostname] = binding
	}
	return view, nil
}

// Withdraw is permanent for this view. A successful future firewall refresh
// needs a newly prepared view and an actuator-owned atomic publication boundary.
func (d *WorkloadDNS) Withdraw() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.withdrawn = true
	d.bindings = nil
}

// Answer accepts only one bounded IN A/AAAA question. It does not perform DNS,
// interpret arbitrary records, or turn a CNAME target into another hostname grant.
// UDP answers are <=512 bytes (truncated when necessary); TCP answers <=4096.
func (d *WorkloadDNS) Answer(raw []byte, tcp bool, now time.Time) ([]byte, error) {
	if d == nil || now.IsZero() || len(raw) > 512 || !wireEnd(raw) || raw[3]&0x40 != 0 {
		return nil, ErrDNS
	}
	var query dnsmessage.Message
	if query.Unpack(raw) != nil || query.Response || query.OpCode != 0 || query.Truncated || query.RCode != 0 || query.Authoritative || query.RecursionAvailable || query.AuthenticData || len(query.Questions) != 1 || len(query.Answers) != 0 || len(query.Authorities) != 0 || !emptyEDNS(query.Additionals) {
		return nil, ErrDNS
	}
	question := query.Questions[0]
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired}, Questions: query.Questions}
	name := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))
	d.mu.RLock()
	defer d.mu.RUnlock()
	if question.Class != dnsmessage.ClassINET || (question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA) || !hostname(name) {
		response.RCode = dnsmessage.RCodeRefused
	} else if d.withdrawn || now.Before(d.issued) || !now.Before(d.expires) {
		response.RCode = dnsmessage.RCodeServerFailure
	} else if binding, ok := d.bindings[name]; !ok {
		response.RCode = dnsmessage.RCodeRefused
	} else {
		// Floor TTL at the entire firewall snapshot's earliest kernel deadline.
		// A response may never outlive another binding that closes forwarding.
		ttl := uint32(d.expires.Sub(now) / time.Second)
		for _, address := range binding.addresses {
			header := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: ttl}
			if question.Type == dnsmessage.TypeA && address.Is4() {
				response.Answers = append(response.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: address.As4()}})
			}
			if question.Type == dnsmessage.TypeAAAA && address.Is6() {
				response.Answers = append(response.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: address.As16()}})
			}
		}
	}
	encoded, err := response.Pack()
	if err != nil {
		return nil, ErrDNS
	}
	limit := 512
	if tcp {
		limit = maxDNSBytes
	}
	if len(encoded) > limit {
		response.Answers = nil
		response.Truncated = true
		encoded, err = response.Pack()
	}
	if err != nil || len(encoded) > limit {
		return nil, ErrDNS
	}
	return encoded, nil
}

// Standard resolvers advertise UDP capacity with an empty EDNS0 OPT record.
// Accept that envelope only; options, flags and larger answer budgets remain
// unsupported. The response keeps the conservative 512-byte UDP limit.
func emptyEDNS(records []dnsmessage.Resource) bool {
	if len(records) == 0 {
		return true
	}
	if len(records) != 1 {
		return false
	}
	r := records[0]
	opt, ok := r.Body.(*dnsmessage.OPTResource)
	return ok && opt != nil && len(opt.Options) == 0 && r.Header.Name.String() == "." && r.Header.Type == dnsmessage.TypeOPT && r.Header.Class >= 512 && r.Header.Class <= 4096 && r.Header.TTL == 0
}
