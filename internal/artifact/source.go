package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

type Source interface {
	Fetch(context.Context, io.Writer) error
}

type SourceFunc func(context.Context, io.Writer) error

func (f SourceFunc) Fetch(ctx context.Context, destination io.Writer) error {
	return f(ctx, destination)
}

type FileSource struct {
	Path string
}

func (s FileSource) Fetch(ctx context.Context, destination io.Writer) error {
	if s.Path == "" {
		return errors.New("fetch file artifact: path is empty")
	}
	file, err := os.Open(s.Path)
	if err != nil {
		return fmt.Errorf("open artifact source: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect artifact source: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("fetch file artifact: source is not a regular file")
	}
	if _, err := io.Copy(destination, &contextReader{ctx: ctx, reader: file}); err != nil {
		return fmt.Errorf("read artifact source: %w", err)
	}
	return nil
}

type HTTPSource struct {
	URL       string
	UserAgent string
	Client    *http.Client
}

func (s HTTPSource) Fetch(ctx context.Context, destination io.Writer) error {
	parsedURL, err := url.ParseRequestURI(s.URL)
	if err != nil {
		return fmt.Errorf("fetch HTTP artifact: invalid URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("fetch HTTP artifact: URL scheme must be http or https")
	}
	if parsedURL.User != nil {
		return errors.New("fetch HTTP artifact: URL credentials are not allowed")
	}
	if s.UserAgent == "" {
		return errors.New("fetch HTTP artifact: user agent is required")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("create artifact request: %w", err)
	}
	request.Header.Set("User-Agent", s.UserAgent)
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("download artifact: %w", ctx.Err())
		}
		return fmt.Errorf("download artifact from %s://%s: request failed", parsedURL.Scheme, parsedURL.Host)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download artifact: unexpected HTTP status %s", response.Status)
	}
	if _, err := io.Copy(destination, &contextReader{ctx: ctx, reader: response.Body}); err != nil {
		return fmt.Errorf("download artifact: %w", err)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
