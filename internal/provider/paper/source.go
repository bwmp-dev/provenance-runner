package paper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

type sourcePolicy interface {
	ValidateInitial(*url.URL) error
	ValidateRedirect(*url.URL) error
}

type httpsAllowlist struct {
	hosts map[string]struct{}
}

func newHTTPSAllowlist(hosts []string) (sourcePolicy, error) {
	allowed := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		normalized, err := normalizeConfiguredHost(host)
		if err != nil {
			return nil, err
		}
		allowed[normalized] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, errors.New("at least one HTTPS artifact host is required")
	}
	return &httpsAllowlist{hosts: allowed}, nil
}

func (p *httpsAllowlist) ValidateInitial(uri *url.URL) error {
	return p.validate(uri)
}

func (p *httpsAllowlist) ValidateRedirect(uri *url.URL) error {
	return p.validate(uri)
}

func (p *httpsAllowlist) validate(uri *url.URL) error {
	host, err := validateHTTPSURLValue(uri)
	if err != nil {
		return err
	}
	if _, exists := p.hosts[host]; !exists {
		return fmt.Errorf("HTTPS artifact host %q is not allowlisted", host)
	}
	return nil
}

type pinnedSourcePolicy struct {
	initial   map[string]struct{}
	redirects map[string]struct{}
}

func newPinnedSourcePolicy(catalog Catalog) (sourcePolicy, error) {
	initial := make(map[string]struct{}, 4)
	redirects := map[string]struct{}{
		"release-assets.githubusercontent.com": {},
		"objects.githubusercontent.com":        {},
	}
	for _, raw := range []string{catalog.Paper.Artifact.URI, catalog.Java.Artifact.URI, catalog.Probe.URI, catalog.PreparedRuntime.Artifact.URI} {
		uri, err := url.ParseRequestURI(raw)
		if err != nil {
			return nil, errors.New("invalid pinned artifact URL")
		}
		host, err := validateHTTPSURLValue(uri)
		if err != nil {
			return nil, err
		}
		initial[uri.String()] = struct{}{}
		redirects[host] = struct{}{}
	}
	return &pinnedSourcePolicy{initial: initial, redirects: redirects}, nil
}

func (p *pinnedSourcePolicy) ValidateInitial(uri *url.URL) error {
	if _, exists := p.initial[uri.String()]; !exists {
		return errors.New("artifact URL does not match a pinned catalog source")
	}
	_, err := validateHTTPSURLValue(uri)
	return err
}

func (p *pinnedSourcePolicy) ValidateRedirect(uri *url.URL) error {
	host, err := validateHTTPSURLValue(uri)
	if err != nil {
		return err
	}
	if _, exists := p.redirects[host]; !exists {
		return fmt.Errorf("pinned artifact redirect host %q is not allowlisted", host)
	}
	return nil
}

type addressResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type resolverAdapter struct {
	resolver *net.Resolver
}

func (r resolverAdapter) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return r.resolver.LookupNetIP(ctx, network, host)
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func clientWithSourcePolicy(client *http.Client, policy sourcePolicy, resolver addressResolver, dialer contextDialer) (*http.Client, error) {
	if client == nil {
		client = &http.Client{}
	}
	configured := *client
	var transport *http.Transport
	switch base := client.Transport.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = base.Clone()
	default:
		return nil, errors.New("artifact HTTP client must use *http.Transport")
	}
	if resolver == nil {
		resolver = resolverAdapter{resolver: net.DefaultResolver}
	}
	if dialer == nil {
		if transport.DialContext != nil {
			dialer = dialerFunc(transport.DialContext)
		} else {
			dialer = &net.Dialer{}
		}
	}
	transport.Proxy = nil
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.DialContext = secureDialContext(resolver, dialer)
	configured.Transport = transport
	existing := client.CheckRedirect
	configured.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if err := policy.ValidateRedirect(request.URL); err != nil {
			return fmt.Errorf("reject artifact redirect: %w", err)
		}
		if existing != nil {
			return existing(request, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &configured, nil
}

func secureDialContext(resolver addressResolver, dialer contextDialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("validate artifact dial address: %w", err)
		}
		addresses, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve artifact host %q: %w", host, err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("resolve artifact host %q: no addresses", host)
		}
		for _, address := range addresses {
			if err := validateResolvedAddress(address); err != nil {
				return nil, fmt.Errorf("resolve artifact host %q: %w", host, err)
			}
		}
		var dialErrors []error
		for _, resolved := range addresses {
			resolved = resolved.Unmap()
			if network == "tcp4" && !resolved.Is4() || network == "tcp6" && !resolved.Is6() {
				continue
			}
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.String(), port))
			if err == nil {
				return connection, nil
			}
			dialErrors = append(dialErrors, err)
		}
		return nil, fmt.Errorf("dial validated artifact host %q: %w", host, errors.Join(dialErrors...))
	}
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func validateResolvedAddress(address netip.Addr) error {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() {
		return fmt.Errorf("address %s is not a permitted public unicast address", address)
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return fmt.Errorf("address %s is in non-public special-purpose range %s", address, prefix)
		}
	}
	return nil
}

func validateHTTPSURLValue(uri *url.URL) (string, error) {
	if uri == nil || uri.Scheme != "https" || uri.Host == "" || uri.User != nil || uri.Fragment != "" {
		return "", errors.New("must be an HTTPS URL without credentials or a fragment")
	}
	if uri.Port() != "" && uri.Port() != "443" {
		return "", errors.New("HTTPS artifact URL must use port 443")
	}
	host := strings.ToLower(strings.TrimSuffix(uri.Hostname(), "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || !validDNSName(host) {
		return "", errors.New("HTTPS artifact host is not public")
	}
	if net.ParseIP(host) != nil {
		return "", errors.New("HTTPS artifact hosts must use allowlisted DNS names, not IP literals")
	}
	return host, nil
}

func normalizeConfiguredHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || strings.ContainsAny(host, "/@#?") || strings.Contains(host, ":") || host == "localhost" || strings.HasSuffix(host, ".localhost") || net.ParseIP(host) != nil || !validDNSName(host) {
		return "", fmt.Errorf("invalid artifact host %q", host)
	}
	return host, nil
}

func validDNSName(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
