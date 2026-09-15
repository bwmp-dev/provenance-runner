//go:build linux

package networkpolicy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
)

type HostUplink struct {
	journal                *HostUplinkJournal
	private                *PrivateJobLink
	pair                   *PrivateJobLink // retained tools/namespaces only; not a workload-link owner
	record                 uplinkRecord
	router, host           privateLinkIdentity
	layout                 [32]byte
	created, ready, closed bool
}

func (j *HostUplinkJournal) inventory(ctx context.Context) ([]privateLinkIdentity, error) {
	raw, err := j.execute(ctx, "-j", "-d", "link", "show")
	var links []privateLinkIdentity
	if err != nil || json.Unmarshal(raw, &links) != nil || len(links) == 0 || len(links) > 16 {
		return nil, ErrNamespace
	}
	seen := map[string]bool{}
	for _, link := range links {
		if link.Index <= 0 || link.Name == "" || seen[link.Name] {
			return nil, ErrNamespace
		}
		seen[link.Name] = true
	}
	return links, nil
}

var uplinkPrefixes = []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24"), netip.MustParsePrefix("10.0.2.0/24"), netip.MustParsePrefix("fd00:1::/64"), netip.MustParsePrefix("fd00:2::/64")}

func overlapsUplink(prefix netip.Prefix) bool {
	for _, owned := range uplinkPrefixes {
		if owned.Overlaps(prefix) {
			return true
		}
	}
	return false
}

func (j *HostUplinkJournal) prefixesAvailable(ctx context.Context) error {
	for _, family := range []string{"-4", "-6"} {
		raw, err := j.execute(ctx, "-j", family, "route", "show", "table", "all")
		var rows []struct {
			Destination string `json:"dst"`
		}
		if err != nil || json.Unmarshal(raw, &rows) != nil || len(rows) > 256 {
			return ErrNamespace
		}
		for _, row := range rows {
			if row.Destination == "default" {
				continue
			}
			prefix, err := netip.ParsePrefix(row.Destination)
			if err != nil {
				address, e := netip.ParseAddr(row.Destination)
				if e != nil {
					return ErrNamespace
				}
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
			if overlapsUplink(prefix) {
				return ErrNamespace
			}
		}
	}
	raw, err := j.execute(ctx, "-j", "addr", "show")
	var links []struct {
		Addresses []struct {
			Local string `json:"local"`
			Bits  int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err != nil || json.Unmarshal(raw, &links) != nil || len(links) > 16 {
		return ErrNamespace
	}
	for _, link := range links {
		for _, item := range link.Addresses {
			address, err := netip.ParseAddr(item.Local)
			if err != nil {
				return ErrNamespace
			}
			prefix := netip.PrefixFrom(address, item.Bits)
			if !prefix.IsValid() || overlapsUplink(prefix) {
				return ErrNamespace
			}
		}
	}
	return nil
}

// Create wires only the fixed private router uplink and its host-side return
// routes. It enables no host forwarding or NAT. Every non-nil result is owned
// by the caller, including partial failures, until Close succeeds.
func (j *HostUplinkJournal) Create(ctx context.Context, job *p.JobSpecification, private *PrivateJobLink) (*HostUplink, error) {
	if j == nil || ctx == nil || ctx.Err() != nil || private == nil || private.ValidatePrepared(ctx) != nil {
		return nil, ErrNamespace
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || !j.ready || j.active != nil || j.prefixesAvailable(ctx) != nil {
		return nil, ErrNamespace
	}
	authority, err := NewAuthority(job)
	if err != nil || private.carrier.job != authority.lease.JobId {
		return nil, ErrNamespace
	}
	carrier, err := NewRetainedRoute(authority.lease.JobId, private.carrier.router, private.carrier.workload, j.tools)
	if err != nil {
		return nil, err
	}
	pair := &PrivateJobLink{carrier: carrier}
	fd, err := unix.FcntlInt(j.network.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		carrier.Close()
		return nil, ErrNamespace
	}
	pair.peer = os.NewFile(uintptr(fd), "owned-host-uplink-namespace")
	discard := func() (*HostUplink, error) { carrier.Close(); pair.peer.Close(); return nil, ErrNamespace }
	if sameNamespace(carrier.network, pair.peer, unix.CLONE_NEWNET) {
		return discard()
	}
	links, err := pair.inventory(ctx, carrier.network)
	if err != nil || len(links) != 2 {
		return discard()
	}
	for _, link := range links {
		if link.Name != "lo" && link.Name != "job0" {
			return discard()
		}
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return discard()
	}
	r := uplinkRecord{Version: 1, Token: hex.EncodeToString(nonce[:]), Boot: j.boot, NetworkDev: j.dev, NetworkIno: j.ino, Job: authority.lease.JobId, Lease: authority.lease.LeaseId, Execution: authority.lease.ExecutionId, Attempt: authority.attempt.AttemptId, Candidate: authority.attempt.ReleaseCandidateId, Matrix: authority.attempt.MatrixEntryId, AttemptNumber: authority.attempt.AttemptNumber, Policy: hex.EncodeToString(authority.digest[:])}
	links, err = j.inventory(ctx)
	if err != nil {
		return discard()
	}
	for _, link := range links {
		if link.Name == r.hostName() {
			return discard()
		}
	}
	if j.writeRecord(r) != nil {
		j.ready = false
		return discard()
	}
	pair.token = r.alias()
	h := &HostUplink{journal: j, private: private, pair: pair, record: r}
	j.active = h
	h.created = true // A timed-out command may already have created its pair.
	if _, err := pair.execute(ctx, carrier.network, "link", "add", "name", r.routerStage(), "type", "veth", "peer", "name", r.hostName()); err != nil {
		return h, err
	}
	if _, err := pair.execute(ctx, carrier.network, "link", "set", "dev", r.routerStage(), "alias", r.alias()+":router", "name", "wan0"); err != nil {
		return h, err
	}
	identity, present, err := pair.identity(ctx, carrier.network, "wan0", ":router")
	if err != nil || !present {
		return h, ErrNamespace
	}
	h.router = identity
	if _, err := pair.execute(ctx, carrier.network, "link", "set", "dev", r.hostName(), "alias", r.alias()+":host"); err != nil {
		return h, err
	}
	if _, err := pair.execute(ctx, carrier.network, "link", "set", "dev", r.hostName(), "netns", "/proc/self/fd/6"); err != nil {
		return h, err
	}
	identity, present, err = pair.identity(ctx, pair.peer, r.hostName(), ":host")
	if err != nil || !present {
		return h, ErrNamespace
	}
	h.host = identity
	identity, present, err = pair.identity(ctx, carrier.network, "wan0", ":router")
	if err != nil || !present || identity.Peer != h.host.Index || h.host.Peer != identity.Index {
		return h, ErrNamespace
	}
	h.router = identity
	if err := h.configure(ctx); err != nil {
		return h, err
	}
	h.layout, err = h.observeLayout(ctx)
	if err != nil || private.ValidatePrepared(ctx) != nil {
		return h, ErrNamespace
	}
	h.ready = true
	return h, nil
}

func (h *HostUplink) matchesJob(job *p.JobSpecification) bool {
	if h == nil {
		return false
	}
	a, err := NewAuthority(job)
	if err != nil {
		return false
	}
	r := h.record
	return r.Job == a.lease.JobId && r.Lease == a.lease.LeaseId && r.Execution == a.lease.ExecutionId && r.Attempt == a.attempt.AttemptId && r.Candidate == a.attempt.ReleaseCandidateId && r.Matrix == a.attempt.MatrixEntryId && r.AttemptNumber == a.attempt.AttemptNumber && r.Policy == hex.EncodeToString(a.digest[:])
}

func (h *HostUplink) Validate(ctx context.Context) error {
	if h == nil || h.journal == nil {
		return ErrNamespace
	}
	j := h.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	refuse := func() error { h.ready = false; return ErrNamespace }
	if ctx == nil || h.closed || !h.ready || j.closed || j.active != h || h.private.Validate(ctx) != nil {
		return refuse()
	}
	r, err := j.readRecord(h.record.Token + ".json")
	if err != nil || r != h.record {
		return refuse()
	}
	a, present, e1 := h.pair.identity(ctx, h.pair.carrier.network, "wan0", ":router")
	b, other, e2 := h.pair.identity(ctx, h.pair.peer, h.record.hostName(), ":host")
	if e1 != nil || e2 != nil || !present || !other || a != h.router || b != h.host {
		return refuse()
	}
	layout, err := h.observeLayout(ctx)
	if err != nil || layout != h.layout {
		return refuse()
	}
	return nil
}

// Close deletes only the original router-side pair through its retained
// namespace. A changed host identity refuses deletion; recovery never guesses.
func (h *HostUplink) Close(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if h.journal == nil || ctx == nil {
		return ErrNamespace
	}
	j := h.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	if h.closed {
		return nil
	}
	h.ready = false
	if j.closed || j.active != h {
		return ErrNamespace
	}
	r, err := j.readRecord(h.record.Token + ".json")
	if err != nil || r != h.record {
		return ErrNamespace
	}
	if h.created {
		a, present, err := h.pair.identity(ctx, h.pair.carrier.network, "wan0", ":router")
		if err != nil {
			return err
		}
		if !present {
			links, err := h.pair.inventory(ctx, h.pair.carrier.network)
			if err != nil {
				return err
			}
			for _, link := range links {
				if link.Name == r.routerStage() {
					if link.Info.Kind != "veth" || (link.Alias != "" && link.Alias != r.alias()+":router") {
						return ErrNamespace
					}
					a, present = link, true
				}
			}
		}
		if present {
			if h.router.Index != 0 && (a.Index != h.router.Index || a.Address != h.router.Address) {
				return ErrNamespace
			}
			peer, other, err := h.pair.identity(ctx, h.pair.peer, r.hostName(), ":host")
			if err != nil {
				return err
			}
			if h.host.Index != 0 && (!other || peer != h.host || a.Peer != peer.Index) {
				return ErrNamespace
			}
			if other && (peer.Peer != a.Index || a.Peer != peer.Index) {
				return ErrNamespace
			}
			if _, err := h.pair.execute(ctx, h.pair.carrier.network, "link", "delete", "dev", a.Name); err != nil {
				return err
			}
		}
		for _, namespace := range []*os.File{h.pair.carrier.network, h.pair.peer} {
			links, err := h.pair.inventory(ctx, namespace)
			if err != nil {
				return err
			}
			for _, link := range links {
				if link.Name == r.hostName() || link.Name == r.routerStage() || (namespace == h.pair.carrier.network && link.Name == "wan0") {
					return ErrNamespace
				}
			}
		}
	}
	if j.prefixesAvailable(ctx) != nil {
		return ErrNamespace
	}
	if err := j.retireRecord(r); err != nil {
		return err
	}
	err = errors.Join(h.pair.carrier.Close(), h.pair.peer.Close())
	if err != nil {
		return err
	}
	h.closed = true
	j.active = nil
	return nil
}
