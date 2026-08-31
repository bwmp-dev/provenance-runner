package paper

import (
	"errors"
	"fmt"
	"net"
	"net/http"
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
	initial := make(map[string]struct{}, 2)
	redirects := map[string]struct{}{
		"release-assets.githubusercontent.com": {},
		"objects.githubusercontent.com":        {},
	}
	for _, raw := range []string{catalog.Paper.Artifact.URI, catalog.Java.Artifact.URI} {
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

func clientWithRedirectPolicy(client *http.Client, policy sourcePolicy) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	configured := *client
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
	return &configured
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
