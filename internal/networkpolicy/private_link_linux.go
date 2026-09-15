//go:build linux

package networkpolicy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
)

type privateLinkIdentity struct {
	Index    int    `json:"ifindex"`
	Peer     int    `json:"link_index"`
	Name     string `json:"ifname"`
	Alias    string `json:"ifalias"`
	Address  string `json:"address"`
	LinkType string `json:"link_type"`
	Info     struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

// PrivateJobLink owns only a new veth pair between two retained private child
// namespaces. It never touches host links, addresses, forwarding or firewalls.
// Cold recovery still requires killing both journaled owners and closing every
// namespace reference before capacity can be released.
type PrivateJobLink struct {
	mu                           sync.Mutex
	carrier                      *RetainedRoute
	peer                         *os.File
	token                        string
	stagedRouter, stagedPeer     string
	routerIdentity, peerIdentity privateLinkIdentity
	created, ready, closed       bool
	closeErr                     error
	layout                       [32]byte
	layoutParts                  [8][32]byte
}

func (l *PrivateJobLink) execute(ctx context.Context, namespace *os.File, args ...string) ([]byte, error) {
	return executeRetainedTool(ctx, namespace, l.carrier.tools.NSenter, l.carrier.tools.IP, []*os.File{l.peer}, "", args...)
}

func (l *PrivateJobLink) inventory(ctx context.Context, namespace *os.File) ([]privateLinkIdentity, error) {
	raw, err := l.execute(ctx, namespace, "-j", "-d", "link", "show")
	var links []privateLinkIdentity
	if err != nil || json.Unmarshal(raw, &links) != nil || len(links) == 0 || len(links) > 16 {
		return nil, ErrNamespace
	}
	seen := map[string]bool{}
	for _, link := range links {
		if link.Name == "" || link.Index <= 0 || seen[link.Name] {
			return nil, ErrNamespace
		}
		seen[link.Name] = true
	}
	return links, nil
}

func (l *PrivateJobLink) identity(ctx context.Context, namespace *os.File, name, suffix string) (privateLinkIdentity, bool, error) {
	links, err := l.inventory(ctx, namespace)
	if err != nil {
		return privateLinkIdentity{}, false, err
	}
	for _, link := range links {
		if link.Name == name {
			if link.Alias != l.token+suffix || link.Info.Kind != "veth" || link.Address == "" {
				return privateLinkIdentity{}, true, ErrNamespace
			}
			return link, true, nil
		}
	}
	return privateLinkIdentity{}, false, nil
}

// CreatePrivateJobLink requires two fresh private namespaces containing only
// loopback. Every non-nil result must be closed even on failure. An existing
// interface is never adopted; a generated alias identifies partial creation.
func CreatePrivateJobLink(ctx context.Context, job string, router, workload *ChildNamespaces, tools RouteTools) (*PrivateJobLink, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrNamespace
	}
	carrier, err := NewRetainedRoute(job, router, workload, tools)
	if err != nil {
		return nil, err
	}
	l := &PrivateJobLink{carrier: carrier}
	l.peer, err = workload.NetworkForJob(job)
	if err != nil {
		carrier.Close()
		return nil, ErrNamespace
	}
	for _, namespace := range []*os.File{carrier.network, l.peer} {
		links, err := l.inventory(ctx, namespace)
		if err != nil || len(links) != 1 || links[0].Name != "lo" || links[0].LinkType != "loopback" {
			l.Close(context.Background())
			return nil, ErrNamespace
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		l.Close(context.Background())
		return nil, ErrNamespace
	}
	l.token = "provenance:" + job + ":" + hex.EncodeToString(nonce[:])
	l.stagedRouter = "pr" + hex.EncodeToString(nonce[:])[:13]
	l.stagedPeer = "pw" + hex.EncodeToString(nonce[:])[:13]
	l.created = true // A timed-out create may have mutated the retained namespace.
	if _, err := l.execute(ctx, carrier.network, "link", "add", "name", l.stagedRouter, "type", "veth", "peer", "name", l.stagedPeer); err != nil {
		return l, err
	}
	// The pinned iproute2 does not preserve an outer veth alias on creation.
	// Random staging names retain ownership until alias and final name are set.
	if _, err := l.execute(ctx, carrier.network, "link", "set", "dev", l.stagedRouter, "alias", l.token+":router", "name", "job0"); err != nil {
		return l, err
	}
	identity, present, err := l.identity(ctx, carrier.network, "job0", ":router")
	if err != nil || !present {
		return l, ErrNamespace
	}
	l.routerIdentity = identity
	if _, err := l.execute(ctx, carrier.network, "link", "set", "dev", l.stagedPeer, "alias", l.token+":workload", "name", "eth0"); err != nil {
		return l, err
	}
	// The destination is a passed namespace FD, never a reusable PID lookup.
	if _, err := l.execute(ctx, carrier.network, "link", "set", "dev", "eth0", "netns", "/proc/self/fd/6"); err != nil {
		return l, err
	}
	identity, present, err = l.identity(ctx, l.peer, "eth0", ":workload")
	if err != nil || !present {
		return l, ErrNamespace
	}
	l.peerIdentity = identity
	// Peer ifindex may change during namespace transfer; capture both afterward.
	identity, present, err = l.identity(ctx, carrier.network, "job0", ":router")
	if err != nil || !present {
		return l, ErrNamespace
	}
	l.routerIdentity = identity
	if router.Validate(job) != nil || workload.Validate(job) != nil || l.routerIdentity.Peer != l.peerIdentity.Index || l.peerIdentity.Peer != l.routerIdentity.Index {
		return l, ErrNamespace
	}
	if err := l.configureLayout(ctx); err != nil {
		return l, err
	}
	l.layout, err = l.observeLayout(ctx)
	if err != nil {
		return l, err
	}
	l.ready = true
	return l, nil
}

func (l *PrivateJobLink) Validate(ctx context.Context) error {
	return l.validate(ctx, false)
}

// ValidatePrepared verifies the full host layout before the Sentry launch gate.
// Runtime link identity validation is separate from this pre-exec observation.
func (l *PrivateJobLink) ValidatePrepared(ctx context.Context) error {
	return l.validate(ctx, true)
}

func (l *PrivateJobLink) validate(ctx context.Context, prepared bool) error {
	if l == nil {
		return ErrNamespace
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || !l.ready || l.carrier.router.Validate(l.carrier.job) != nil || l.carrier.workload.Validate(l.carrier.job) != nil {
		l.ready = false
		return ErrNamespace
	}
	a, present, e1 := l.identity(ctx, l.carrier.network, "job0", ":router")
	b, other, e2 := l.identity(ctx, l.peer, "eth0", ":workload")
	if e1 != nil || e2 != nil || !present || !other || a != l.routerIdentity || b != l.peerIdentity {
		l.ready = false
		return ErrNamespace
	}
	if !prepared {
		return nil
	}
	if layout, err := l.observeLayout(ctx); err != nil || layout != l.layout {
		l.ready = false
		if err != nil {
			return err
		}
		return ErrNamespace
	}
	return nil
}

// Close refuses a changed/foreign link. It can clean up after either child has
// exited using the original namespace descriptors. It is retryable/idempotent.
func (l *PrivateJobLink) Close(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return l.closeErr
	}
	l.ready = false
	if l.created {
		a, present, err := l.identity(ctx, l.carrier.network, "job0", ":router")
		if err != nil {
			return err
		}
		if !present {
			links, err := l.inventory(ctx, l.carrier.network)
			if err != nil {
				return err
			}
			for _, link := range links {
				if link.Name == l.stagedRouter {
					if link.Info.Kind != "veth" || (link.Alias != "" && link.Alias != l.token+":router") {
						return ErrNamespace
					}
					a, present = link, true
				}
			}
		}
		if present {
			if l.routerIdentity.Index != 0 && (a.Index != l.routerIdentity.Index || a.Address != l.routerIdentity.Address) {
				return ErrNamespace
			}
			if l.peerIdentity.Index != 0 {
				peer, present, err := l.identity(ctx, l.peer, "eth0", ":workload")
				if err != nil || !present || peer != l.peerIdentity || a.Peer != peer.Index {
					return ErrNamespace
				}
			}
			if _, err := l.execute(ctx, l.carrier.network, "link", "delete", "dev", a.Name); err != nil {
				return err
			}
		}
		for _, namespace := range []*os.File{l.carrier.network, l.peer} {
			links, err := l.inventory(ctx, namespace)
			if err != nil {
				return err
			}
			for _, link := range links {
				if link.Name == "job0" || link.Name == "eth0" || link.Name == l.stagedRouter || link.Name == l.stagedPeer {
					return ErrNamespace
				}
			}
		}
	}
	err := l.carrier.Close()
	if l.peer != nil {
		if closeErr := l.peer.Close(); err == nil {
			err = closeErr
		}
	}
	l.closed = true
	l.closeErr = err
	return err
}
