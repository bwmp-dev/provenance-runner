package gatewayclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestValidateCompleteLogUploadRejectsHostPathContentTypeAndExpiryBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	offerExpiry := now.Add(time.Minute)
	leaseExpiry := now.Add(5 * time.Minute)
	tests := []struct {
		name   string
		mutate func(*runnerv1.ObjectUpload)
	}{
		{name: "malformed URI", mutate: func(upload *runnerv1.ObjectUpload) { upload.Uri = "://secret" }},
		{name: "userinfo", mutate: func(upload *runnerv1.ObjectUpload) { upload.Uri = "https://user:secret@logs.example/log.gz" }},
		{name: "localhost", mutate: func(upload *runnerv1.ObjectUpload) { upload.Uri = "https://localhost/log.gz" }},
		{name: "literal IP", mutate: func(upload *runnerv1.ObjectUpload) { upload.Uri = "https://192.0.2.10/log.gz" }},
		{name: "invalid hostname", mutate: func(upload *runnerv1.ObjectUpload) { upload.Uri = "https://-logs.example/log.gz" }},
		{name: "non TLS port", mutate: func(upload *runnerv1.ObjectUpload) { upload.Uri = "https://logs.example:8443/log.gz" }},
		{name: "dot segment", mutate: func(upload *runnerv1.ObjectUpload) { upload.Uri = "https://logs.example/staging/%2e%2e/log.gz" }},
		{name: "content type", mutate: func(upload *runnerv1.ObjectUpload) { upload.ContentType = "application/zstd" }},
		{name: "expiry at lease", mutate: func(upload *runnerv1.ObjectUpload) { upload.ExpiresAt = timestamppb.New(leaseExpiry) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upload := &runnerv1.ObjectUpload{Uri: "https://logs.example/staging/log.gz?signature=private", ContentType: completeLogUploadContentType, ExpiresAt: timestamppb.New(now.Add(9 * time.Minute))}
			test.mutate(upload)
			if target, rejection := validateCompleteLogUpload(upload, now, offerExpiry, leaseExpiry); target != nil || rejection == nil || rejection.Code != "invalid_complete_log_upload" {
				t.Fatalf("validation = target %#v rejection %#v", target, rejection)
			}
		})
	}
}

func TestPublicUploadIPRejectsNonPublicRanges(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "::1", "fc00::1"} {
		if publicUploadIP(net.ParseIP(value)) {
			t.Fatalf("publicUploadIP(%q) = true", value)
		}
	}
	if !publicUploadIP(net.ParseIP("192.0.2.1")) {
		t.Fatal("documentation-range address should exercise the public path")
	}
}

func TestCompleteLogUploaderRetriesExactBytesAndEmitsOnlySafeMetadata(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	log := testCompleteLog(t, []byte("complete log\n"))
	defer closeCompleteLog(log)
	var attempts int
	var bodies [][]byte
	uploader := newHTTPCompleteLogUploader()
	uploader.now = func() time.Time { return now }
	uploader.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		if request.Method != http.MethodPut || request.ContentLength != log.CompressedBytes || request.Header.Get("Content-Type") != completeLogUploadContentType || len(request.Header) != 1 {
			t.Fatalf("request = method %s length %d headers %#v", request.Method, request.ContentLength, request.Header)
		}
		status := http.StatusNoContent
		if attempts < completeLogUploadAttempts {
			status = http.StatusServiceUnavailable
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("response")), Header: make(http.Header)}, nil
	})
	target := &completeLogTarget{uri: "https://logs.example/staging/execution/log.gz?signature=private", objectKey: "staging/execution/log.gz", expiresAt: now.Add(time.Minute)}
	object, err := uploader.Upload(context.Background(), target, log)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != completeLogUploadAttempts || len(bodies) != completeLogUploadAttempts {
		t.Fatalf("attempts = %d bodies = %d", attempts, len(bodies))
	}
	for _, body := range bodies[1:] {
		if !bytes.Equal(body, bodies[0]) {
			t.Fatal("retry body changed")
		}
	}
	if object.GetObjectKey() != target.objectKey || object.GetCompressedSizeBytes() != uint64(log.CompressedBytes) || object.GetContentType() != completeLogUploadContentType || strings.Contains(object.String(), "private") {
		t.Fatalf("log object = %#v", object)
	}
}

func TestCompleteLogUploaderFailsClosedOnRedirectShortReadAndArchiveMismatch(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	target := &completeLogTarget{uri: "https://logs.example/staging/log.gz?signature=do-not-disclose", objectKey: "staging/log.gz", expiresAt: now.Add(time.Minute)}
	tests := []struct {
		name      string
		mutateLog func(*execution.CompleteLog)
		transport roundTripFunc
	}{
		{name: "redirect", transport: func(request *http.Request) (*http.Response, error) {
			_, _ = io.Copy(io.Discard, request.Body)
			return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{"https://other.example/log.gz"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		}},
		{name: "short request consumption", transport: func(request *http.Request) (*http.Response, error) {
			buffer := make([]byte, 1)
			_, _ = request.Body.Read(buffer)
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		}},
		{name: "digest mismatch", mutateLog: func(log *execution.CompleteLog) { log.SHA256 = strings.Repeat("0", 64) }, transport: func(*http.Request) (*http.Response, error) {
			t.Fatal("request was sent for invalid archive")
			return nil, errors.New("unreachable")
		}},
		{name: "size mismatch", mutateLog: func(log *execution.CompleteLog) { log.CompressedBytes++ }, transport: func(*http.Request) (*http.Response, error) {
			t.Fatal("request was sent for invalid archive")
			return nil, errors.New("unreachable")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			log := testCompleteLog(t, []byte("complete log\n"))
			defer closeCompleteLog(log)
			if test.mutateLog != nil {
				test.mutateLog(log)
			}
			uploader := newHTTPCompleteLogUploader()
			uploader.now = func() time.Time { return now }
			uploader.client.Transport = test.transport
			_, err := uploader.Upload(context.Background(), target, log)
			if err == nil {
				t.Fatal("Upload() error = nil")
			}
			if strings.Contains(err.Error(), "do-not-disclose") || strings.Contains(err.Error(), target.uri) {
				t.Fatalf("error disclosed capability: %v", err)
			}
		})
	}
}

func testCompleteLog(t *testing.T, content []byte) *execution.CompleteLog {
	t.Helper()
	archive, err := os.CreateTemp(t.TempDir(), "complete-log-*.gz")
	if err != nil {
		t.Fatal(err)
	}
	writer := gzip.NewWriter(archive)
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := archive.Stat()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.NewSectionReader(archive, 0, info.Size())); err != nil {
		t.Fatal(err)
	}
	return &execution.CompleteLog{State: evidence.CompleteLogStateComplete, ContentType: completeLogSourceContentType, ContentEncoding: completeLogSourceEncoding, SHA256: hex.EncodeToString(digest.Sum(nil)), UncompressedBytes: int64(len(content)), CompressedBytes: info.Size(), Archive: archive}
}
