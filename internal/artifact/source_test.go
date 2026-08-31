package artifact

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPSourceUsesRequiredUserAgent(t *testing.T) {
	const userAgent = "provenance-runner/test"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.UserAgent() != userAgent {
			t.Errorf("User-Agent = %q, want %q", request.UserAgent(), userAgent)
		}
		_, _ = io.WriteString(writer, "artifact")
	}))
	defer server.Close()

	var output strings.Builder
	err := (HTTPSource{URL: server.URL, UserAgent: userAgent, Client: server.Client()}).Fetch(context.Background(), &output)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if output.String() != "artifact" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestHTTPSourceRejectsUnexpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	err := (HTTPSource{URL: server.URL, UserAgent: "provenance-runner/test", Client: server.Client()}).Fetch(context.Background(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("Fetch() error = %v", err)
	}
}

func TestHTTPSourceRequiresSupportedURLAndUserAgent(t *testing.T) {
	tests := []HTTPSource{
		{URL: "file:///artifact.jar", UserAgent: "test"},
		{URL: "https://example.com/artifact.jar"},
		{URL: "https://user:password@example.com/artifact.jar", UserAgent: "test"},
	}
	for _, source := range tests {
		if err := source.Fetch(context.Background(), io.Discard); err == nil {
			t.Fatalf("Fetch(%#v) error = nil", source)
		}
	}
}

func TestFileSourceHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.jar")
	if err := os.WriteFile(path, []byte("artifact"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (FileSource{Path: path}).Fetch(ctx, io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Fetch() error = %v, want context canceled", err)
	}
}
