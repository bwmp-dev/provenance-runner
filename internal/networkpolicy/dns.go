package networkpolicy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const maxDNSBytes = 4096

func (b *Binder) resolve(ctx context.Context, host string) ([]netip.Addr, time.Duration, error) {
	all := map[netip.Addr]bool{}
	ttl := b.maxTTL
	for _, family := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		name, err := dnsmessage.NewName(host + ".")
		if err != nil {
			return nil, 0, ErrDNS
		}
		var random [2]byte
		if _, err = rand.Read(random[:]); err != nil {
			return nil, 0, ErrDNS
		}
		query := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(random[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: family, Class: dnsmessage.ClassINET}}}
		raw, err := query.Pack()
		if err != nil {
			return nil, 0, ErrDNS
		}
		answer, err := b.resolver.Exchange(ctx, raw)
		if err != nil || ctx.Err() != nil || len(answer) > maxDNSBytes {
			return nil, 0, ErrDNS
		}
		addresses, duration, err := b.parse(query, answer)
		if err != nil {
			return nil, 0, err
		}
		ttl = min(ttl, duration)
		for _, addr := range addresses {
			all[addr] = true
		}
	}
	if len(all) == 0 || len(all) > 64 {
		return nil, 0, ErrDNS
	}
	addresses := make([]netip.Addr, 0, len(all))
	for addr := range all {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
	return addresses, ttl, nil
}

func (b *Binder) parse(query dnsmessage.Message, raw []byte) ([]netip.Addr, time.Duration, error) {
	var response dnsmessage.Message
	if len(raw) > maxDNSBytes || !wireEnd(raw) {
		return nil, 0, ErrDNS
	}
	if err := response.Unpack(raw); err != nil || response.ID != query.ID || !response.Response || response.OpCode != 0 || response.Truncated || response.RCode != dnsmessage.RCodeSuccess || len(response.Questions) != 1 || response.Questions[0] != query.Questions[0] || len(response.Answers) > 64 || len(response.Authorities) > 16 || len(response.Additionals) > 16 {
		return nil, 0, ErrDNS
	}
	q := query.Questions[0]
	cnames := map[string]string{}
	addresses := map[string][]netip.Addr{}
	ttl := b.maxTTL
	for _, record := range response.Answers {
		owner := strings.ToLower(strings.TrimSuffix(record.Header.Name.String(), "."))
		if !hostname(owner) || record.Header.Class != dnsmessage.ClassINET || record.Header.TTL == 0 {
			return nil, 0, ErrDNS
		}
		ttl = min(ttl, time.Duration(record.Header.TTL)*time.Second)
		switch value := record.Body.(type) {
		case *dnsmessage.CNAMEResource:
			target := strings.ToLower(strings.TrimSuffix(value.CNAME.String(), "."))
			if !hostname(target) || cnames[owner] != "" || len(addresses[owner]) != 0 {
				return nil, 0, ErrDNS
			}
			cnames[owner] = target
		case *dnsmessage.AResource:
			addr := netip.AddrFrom4(value.A)
			if q.Type != dnsmessage.TypeA || record.Header.Length != 4 || cnames[owner] != "" {
				return nil, 0, ErrDNS
			}
			if !b.public(addr) {
				return nil, 0, ErrDenied
			}
			addresses[owner] = append(addresses[owner], addr)
		case *dnsmessage.AAAAResource:
			addr := netip.AddrFrom16(value.AAAA)
			if q.Type != dnsmessage.TypeAAAA || record.Header.Length != 16 || cnames[owner] != "" {
				return nil, 0, ErrDNS
			}
			if !b.public(addr) {
				return nil, 0, ErrDenied
			}
			addresses[owner] = append(addresses[owner], addr)
		default:
			return nil, 0, ErrDNS
		}
	}
	current := strings.TrimSuffix(q.Name.String(), ".")
	visited := map[string]bool{}
	for cnames[current] != "" {
		if visited[current] || len(visited) >= 8 {
			return nil, 0, ErrDNS
		}
		visited[current] = true
		current = cnames[current]
	}
	if visited[current] || len(visited) != len(cnames) || len(addresses) > 1 || (len(addresses) == 1 && len(addresses[current]) == 0) {
		return nil, 0, ErrDNS
	}
	// A bare NOERROR/NODATA family is allowed; a dangling CNAME is not.
	if len(cnames) != 0 && len(addresses[current]) == 0 {
		return nil, 0, ErrDNS
	}
	return addresses[current], ttl, nil
}

// wireEnd checks only declared lengths and encoded names; dnsmessage performs
// actual label/pointer/body validation. It rejects undeclared trailing payloads.
func wireEnd(raw []byte) bool {
	if len(raw) < 12 {
		return false
	}
	offset := 12
	name := func() bool {
		for labels := 0; labels < 128; labels++ {
			if offset >= len(raw) {
				return false
			}
			length := int(raw[offset])
			offset++
			if length == 0 {
				return true
			}
			if length&0xc0 == 0xc0 {
				if offset >= len(raw) {
					return false
				}
				offset++
				return true
			}
			if length > 63 || offset+length > len(raw) {
				return false
			}
			offset += length
		}
		return false
	}
	for section := 0; section < 4; section++ {
		count := int(binary.BigEndian.Uint16(raw[4+section*2 : 6+section*2]))
		if count > 64 {
			return false
		}
		for i := 0; i < count; i++ {
			if !name() {
				return false
			}
			if section == 0 {
				offset += 4
			} else {
				if offset+10 > len(raw) {
					return false
				}
				size := int(binary.BigEndian.Uint16(raw[offset+8 : offset+10]))
				offset += 10 + size
			}
			if offset > len(raw) {
				return false
			}
		}
	}
	return offset == len(raw)
}
