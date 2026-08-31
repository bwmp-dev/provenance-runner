package paper

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
			source := artifact.HTTPSource{
				URL:       server.URL + "/artifact",
				UserAgent: DownloadUserAgent,
				Client:    clientWithRedirectPolicy(server.Client(), policy),
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
	policy, err := newPinnedSourcePolicy(AlphaCatalog())
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
