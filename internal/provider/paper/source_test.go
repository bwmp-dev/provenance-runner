package paper

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
)

func TestHTTPSAllowlistRejectsHostSideSSRFInputs(t *testing.T) {
	policyValue, err := newHTTPSAllowlist([]string{"artifacts.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	policy := policyValue.(*httpsAllowlist)
	tests := map[string]string{
		"non-HTTPS":       "http://artifacts.example.com/file.jar",
		"credentials":     "https://user:password@artifacts.example.com/file.jar",
		"fragment":        "https://artifacts.example.com/file.jar#secret",
		"disallowed host": "https://internal.example/file.jar",
		"loopback IPv4":   "https://127.0.0.1/file.jar",
		"private IPv4":    "https://10.0.0.7/file.jar",
		"loopback IPv6":   "https://[::1]/file.jar",
		"localhost":       "https://localhost/file.jar",
		"custom port":     "https://artifacts.example.com:8443/file.jar",
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			uri, parseErr := url.Parse(raw)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if err := policy.ValidateInitial(uri); err == nil {
				t.Fatalf("ValidateInitial(%q) error = nil", raw)
			}
		})
	}
	allowed, _ := url.Parse("https://artifacts.example.com/file.jar?signature=value")
	if err := policy.ValidateInitial(allowed); err != nil {
		t.Errorf("allowlisted URL rejected: %v", err)
	}
}

func TestHTTPSAllowlistConfigurationFailsClosed(t *testing.T) {
	for name, hosts := range map[string][]string{
		"empty":       nil,
		"wildcard":    {"*.example.com"},
		"URL":         {"https://example.com"},
		"IP literal":  {"10.0.0.1"},
		"localhost":   {"localhost"},
		"custom port": {"example.com:8443"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newHTTPSAllowlist(hosts); err == nil {
				t.Fatal("newHTTPSAllowlist() error = nil")
			}
		})
	}
}

func TestArtifactRedirectIsRevalidatedBeforeDial(t *testing.T) {
	for name, redirect := range map[string]string{
		"disallowed host": "https://internal.example/secret",
		"private target":  "https://127.0.0.1:443/secret",
	} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				http.Redirect(writer, request, redirect, http.StatusFound)
			}))
			defer server.Close()
			strictValue, err := newHTTPSAllowlist([]string{"artifacts.example.com"})
			if err != nil {
				t.Fatal(err)
			}
			policy := initialURLPolicy{initial: server.URL + "/artifact", redirects: strictValue}
			client, err := clientWithSourcePolicy(server.Client(), policy,
				staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}},
				dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				}),
			)
			if err != nil {
				t.Fatal(err)
			}
			source := artifact.HTTPSource{
				URL:       server.URL + "/artifact",
				UserAgent: DownloadUserAgent,
				Client:    client,
			}
			err = source.Fetch(context.Background(), io.Discard)
			if err == nil || !strings.Contains(err.Error(), "request failed") {
				t.Fatalf("Fetch() error = %v", err)
			}
			if requests.Load() != 1 {
				t.Fatalf("initial server requests = %d, want 1; redirect should be rejected before another dial", requests.Load())
			}
		})
	}
}

func TestPinnedSourcesRequireExactInitialURLsAndKnownRedirectHosts(t *testing.T) {
	catalog := AlphaCatalog()
	catalog.Probe = ArtifactPin{URI: "https://github.com/bwmp-dev/provenance/releases/download/probe/probe.jar", SHA256: strings.Repeat("a", 64), Filename: "probe.jar", SizeBytes: 1}
	catalog.PreparedRuntime = ArchivePin{Artifact: ArtifactPin{URI: "https://github.com/bwmp-dev/provenance-runner/releases/download/runtime/runtime.tar.gz", SHA256: strings.Repeat("b", 64), Filename: "runtime.tar.gz", SizeBytes: 1}, MaximumExpandedBytes: 1}
	policy, err := newPinnedSourcePolicy(catalog)
	if err != nil {
		t.Fatal(err)
	}
	paperURL, _ := url.Parse(AlphaCatalog().Paper.Artifact.URI)
	if err := policy.ValidateInitial(paperURL); err != nil {
		t.Errorf("pinned Paper URL rejected: %v", err)
	}
	changedPath, _ := url.Parse("https://fill-data.papermc.io/v1/objects/different/paper.jar")
	if err := policy.ValidateInitial(changedPath); err == nil {
		t.Error("changed pinned source accepted")
	}
	officialRedirect, _ := url.Parse("https://release-assets.githubusercontent.com/github-production-release-asset/file")
	if err := policy.ValidateRedirect(officialRedirect); err != nil {
		t.Errorf("official release redirect rejected: %v", err)
	}
	privateRedirect, _ := url.Parse("https://10.0.0.1/file")
	if err := policy.ValidateRedirect(privateRedirect); err == nil {
		t.Error("private redirect accepted")
	}
	disallowedRedirect, _ := url.Parse("https://internal.example/file")
	if err := policy.ValidateRedirect(disallowedRedirect); err == nil {
		t.Error("disallowed redirect accepted")
	}
}

func TestSecureDialRejectsNonPublicAndMetadataResolution(t *testing.T) {
	for name, address := range map[string]string{
		"unspecified IPv4":         "0.0.0.0",
		"loopback IPv4":            "127.0.0.1",
		"private IPv4":             "10.0.0.1",
		"link-local IPv4":          "169.254.169.254",
		"metadata IPv4":            "100.100.100.200",
		"CGNAT IPv4":               "100.64.0.1",
		"protocol assignment IPv4": "192.0.0.9",
		"documentation IPv4":       "192.0.2.1",
		"benchmark IPv4":           "198.18.0.1",
		"documentation 2 IPv4":     "198.51.100.1",
		"documentation 3 IPv4":     "203.0.113.1",
		"reserved IPv4":            "240.0.0.1",
		"multicast IPv4":           "224.0.0.1",
		"unspecified IPv6":         "::",
		"loopback IPv6":            "::1",
		"private IPv6":             "fd00::1",
		"link-local IPv6":          "fe80::1",
		"multicast IPv6":           "ff02::1",
		"discard IPv6":             "100::1",
		"protocol assignment IPv6": "2001::1",
		"documentation IPv6":       "2001:db8::1",
		"documentation 2 IPv6":     "3fff::1",
		"reserved IPv6":            "5f00::1",
		"mapped private IPv6":      "::ffff:127.0.0.1",
	} {
		t.Run(name, func(t *testing.T) {
			var dials atomic.Int32
			dial := secureDialContext(
				staticResolver{addresses: []netip.Addr{netip.MustParseAddr(address)}},
				dialerFunc(func(context.Context, string, string) (net.Conn, error) {
					dials.Add(1)
					return nil, errors.New("unexpected dial")
				}),
			)
			if _, err := dial(context.Background(), "tcp", "artifacts.example.com:443"); err == nil {
				t.Fatal("secure dial error = nil")
			}
			if dials.Load() != 0 {
				t.Fatalf("dial count = %d", dials.Load())
			}
		})
	}
}

func TestSecureDialPinsResolvedAddressAndRejectsRebindingSet(t *testing.T) {
	public := netip.MustParseAddr("93.184.216.34")
	var dialed string
	dial := secureDialContext(staticResolver{addresses: []netip.Addr{public}}, dialerFunc(func(_ context.Context, _ string, address string) (net.Conn, error) {
		dialed = address
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}))
	connection, err := dial(context.Background(), "tcp", "artifacts.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if dialed != "93.184.216.34:443" {
		t.Fatalf("dialed address = %q", dialed)
	}

	var rebindingDials atomic.Int32
	rebinding := secureDialContext(staticResolver{addresses: []netip.Addr{public, netip.MustParseAddr("127.0.0.1")}}, dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		rebindingDials.Add(1)
		return nil, errors.New("unexpected dial")
	}))
	if _, err := rebinding(context.Background(), "tcp", "artifacts.example.com:443"); err == nil {
		t.Fatal("rebinding resolution error = nil")
	}
	if rebindingDials.Load() != 0 {
		t.Fatalf("rebinding dial count = %d", rebindingDials.Load())
	}
}

func TestHTTPSClientClearsLegacyTLSDialBypass(t *testing.T) {
	policy, err := newHTTPSAllowlist([]string{"artifacts.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	var legacyTLSDials atomic.Int32
	var validatedDials atomic.Int32
	client, err := clientWithSourcePolicy(&http.Client{Transport: &http.Transport{
		DialTLS: func(string, string) (net.Conn, error) {
			legacyTLSDials.Add(1)
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
	}}, policy, staticResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		validatedDials.Add(1)
		return nil, errors.New("unexpected validated dial")
	}))
	if err != nil {
		t.Fatal(err)
	}
	source := artifact.HTTPSource{URL: "https://artifacts.example.com/file.jar", UserAgent: DownloadUserAgent, Client: client}
	if err := source.Fetch(context.Background(), io.Discard); err == nil {
		t.Fatal("Fetch() error = nil")
	}
	if legacyTLSDials.Load() != 0 || validatedDials.Load() != 0 {
		t.Fatalf("legacy/validated dial counts = %d/%d, want 0/0", legacyTLSDials.Load(), validatedDials.Load())
	}
}

type initialURLPolicy struct {
	initial   string
	redirects sourcePolicy
}

func (p initialURLPolicy) ValidateInitial(uri *url.URL) error {
	if uri.String() != p.initial {
		return &url.Error{Op: "validate", URL: uri.String(), Err: http.ErrNotSupported}
	}
	return nil
}

func (p initialURLPolicy) ValidateRedirect(uri *url.URL) error {
	return p.redirects.ValidateRedirect(uri)
}
