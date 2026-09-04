package gatewayclient

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

const (
	completeLogUploadContentType = "application/gzip"
	completeLogSourceContentType = "text/plain; charset=utf-8"
	completeLogSourceEncoding    = "gzip"
	maximumUploadURIBytes        = 4096
	maximumObjectKeyBytes        = 1024
	maximumCompressedUploadBytes = evidence.MaximumCompleteLogBytes + (1 << 20)
	maximumUploadResponseBytes   = 64 << 10
	completeLogUploadAttempts    = 3
)

type completeLogTarget struct {
	uri       string
	objectKey string
	expiresAt time.Time
}

type activeCompleteLogUpload struct {
	leaseID   string
	attemptID string
	target    *completeLogTarget
}

type completeLogUploader interface {
	Upload(context.Context, *completeLogTarget, *execution.CompleteLog) (*runnerv1.LogObject, error)
}

func (c *Client) setCompleteLogTarget(job *runnerv1.JobSpecification, target *completeLogTarget) {
	c.uploadMu.Lock()
	defer c.uploadMu.Unlock()
	c.activeUpload = nil
	if target != nil && job != nil && job.GetLease() != nil && job.GetAttempt() != nil {
		copyTarget := *target
		c.activeUpload = &activeCompleteLogUpload{leaseID: job.GetLease().GetLeaseId(), attemptID: job.GetAttempt().GetAttemptId(), target: &copyTarget}
	}
}

func (c *Client) completeLogTarget(lease *runnerv1.LeaseIdentity, attempt *runnerv1.AttemptIdentity) *completeLogTarget {
	c.uploadMu.Lock()
	defer c.uploadMu.Unlock()
	if c.activeUpload == nil || lease == nil || attempt == nil || c.activeUpload.leaseID != lease.GetLeaseId() || c.activeUpload.attemptID != attempt.GetAttemptId() {
		return nil
	}
	copyTarget := *c.activeUpload.target
	return &copyTarget
}

func (c *Client) clearCompleteLogTarget() {
	c.uploadMu.Lock()
	c.activeUpload = nil
	c.uploadMu.Unlock()
}

type httpCompleteLogUploader struct {
	client *http.Client
	now    func() time.Time
}

func newHTTPCompleteLogUploader() *httpCompleteLogUploader {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           secureUploadDialer(dialer),
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
	}
	return &httpCompleteLogUploader{
		client: &http.Client{
			Transport: transport,
			Timeout:   2 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("complete log upload redirects are not allowed")
			},
		},
		now: time.Now,
	}
}

func secureUploadDialer(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("complete log upload destination is invalid")
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addresses) == 0 {
			return nil, errors.New("complete log upload destination could not be resolved")
		}
		for _, address := range addresses {
			if !publicUploadIP(address.IP) {
				continue
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
		}
		return nil, errors.New("complete log upload destination resolved only to non-public addresses")
	}
}

func publicUploadIP(ip net.IP) bool {
	address, valid := netip.AddrFromSlice(ip)
	if !valid {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range nonPublicUploadPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// netip.Addr.IsGlobalUnicast intentionally includes private and other
// special-purpose unicast ranges. Keep an explicit denylist for destinations
// that must never be reachable through an upload capability. IPv4-mapped IPv6
// addresses are normalized with Unmap before this table is consulted.
var nonPublicUploadPrefixes = []netip.Prefix{
	// IPv4 special-purpose and non-global ranges.
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
	netip.MustParsePrefix("240.0.0.0/4"),

	// IPv6 translation, local, discard, protocol-assignment, documentation,
	// deprecated transition, and other special-use ranges.
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("fe80::/10"),
}

func validateCompleteLogUpload(upload *runnerv1.ObjectUpload, now, offerExpiresAt, leaseExpiresAt time.Time) (*completeLogTarget, *OfferRejection) {
	if upload == nil {
		return nil, nil
	}
	if len(upload.ProtoReflect().GetUnknown()) != 0 {
		return nil, rejectUnsupported("invalid_complete_log_upload", "complete log upload contains unsupported fields")
	}
	if len(upload.GetUri()) == 0 || len(upload.GetUri()) > maximumUploadURIBytes || !utf8.ValidString(upload.GetUri()) {
		return nil, rejectUnsupported("invalid_complete_log_upload", "complete log upload URI is missing or invalid")
	}
	parsed, err := url.ParseRequestURI(upload.GetUri())
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, rejectUnsupported("invalid_complete_log_upload", "complete log upload URI must be an absolute HTTPS URL")
	}
	hostname := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if !validUploadHostname(hostname) || hostname == "localhost" || net.ParseIP(hostname) != nil || (parsed.Port() != "" && parsed.Port() != "443") {
		return nil, rejectUnsupported("invalid_complete_log_upload", "complete log upload destination is not supported")
	}
	if upload.GetContentType() != completeLogUploadContentType {
		return nil, rejectUnsupported("invalid_complete_log_upload", "complete log upload content type must be application/gzip")
	}
	if err := validateTimestamp("completeLogUpload.expiresAt", upload.GetExpiresAt()); err != nil {
		return nil, rejectUnsupported("invalid_complete_log_upload", "complete log upload expiration is missing or invalid")
	}
	expiresAt := upload.GetExpiresAt().AsTime()
	if !expiresAt.After(now) || expiresAt.Before(offerExpiresAt) || !expiresAt.After(leaseExpiresAt) || expiresAt.After(now.Add(maximumLeaseDuration)) {
		return nil, rejectUnsupported("invalid_complete_log_upload", "complete log upload expiration is outside the lease window")
	}
	objectKey, err := safeUploadObjectKey(parsed)
	if err != nil {
		return nil, rejectUnsupported("invalid_complete_log_upload", "complete log upload object key is invalid")
	}
	return &completeLogTarget{uri: upload.GetUri(), objectKey: objectKey, expiresAt: expiresAt}, nil
}

func validUploadHostname(hostname string) bool {
	if hostname == "" || len(hostname) > 253 {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
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

func safeUploadObjectKey(parsed *url.URL) (string, error) {
	if strings.Contains(parsed.EscapedPath(), "%") {
		return "", errors.New("encoded object keys are not supported")
	}
	path, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		return "", err
	}
	key := strings.TrimPrefix(path, "/")
	if key == "" || len(key) > maximumObjectKeyBytes || !utf8.ValidString(key) || strings.Contains(key, "\\") {
		return "", errors.New("invalid object key")
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", errors.New("invalid object key segment")
		}
		for _, character := range segment {
			if character == 0 || unicode.IsControl(character) {
				return "", errors.New("invalid object key character")
			}
		}
	}
	return key, nil
}

func (u *httpCompleteLogUploader) Upload(ctx context.Context, target *completeLogTarget, completeLog *execution.CompleteLog) (*runnerv1.LogObject, error) {
	if u == nil || u.client == nil || u.now == nil || target == nil {
		return nil, errors.New("complete log upload is unavailable")
	}
	if !target.expiresAt.After(u.now().UTC()) {
		return nil, errors.New("complete log upload capability has expired")
	}
	digest, size, err := validateUploadArchive(completeLog)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < completeLogUploadAttempts; attempt++ {
		if !target.expiresAt.After(u.now().UTC()) {
			return nil, errors.New("complete log upload capability expired before completion")
		}
		reader := &countingReader{reader: io.NewSectionReader(completeLog.Archive, 0, size)}
		request, err := http.NewRequestWithContext(ctx, http.MethodPut, target.uri, reader)
		if err != nil {
			return nil, errors.New("create complete log upload request")
		}
		request.ContentLength = size
		request.Header.Set("Content-Type", completeLogUploadContentType)
		response, requestErr := u.client.Do(request)
		if requestErr != nil {
			lastErr = errors.New("complete log upload request failed")
			continue
		}
		_, copyErr := io.Copy(io.Discard, io.LimitReader(response.Body, maximumUploadResponseBytes+1))
		closeErr := response.Body.Close()
		if copyErr != nil || closeErr != nil {
			lastErr = errors.New("complete log upload response could not be consumed")
			continue
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			if reader.count != size {
				return nil, errors.New("complete log upload did not consume the complete archive")
			}
			return &runnerv1.LogObject{
				ObjectKey:           target.objectKey,
				Digest:              &runnerv1.Digest{Algorithm: runnerv1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digest},
				CompressedSizeBytes: uint64(size),
				ContentType:         completeLogUploadContentType,
			}, nil
		}
		lastErr = fmt.Errorf("complete log upload returned HTTP status %d", response.StatusCode)
		if response.StatusCode < 500 || response.StatusCode > 599 {
			return nil, lastErr
		}
	}
	if lastErr == nil {
		lastErr = errors.New("complete log upload failed")
	}
	return nil, lastErr
}

func validateUploadArchive(completeLog *execution.CompleteLog) ([]byte, int64, error) {
	if completeLog == nil || completeLog.Archive == nil {
		return nil, 0, errors.New("complete log archive is unavailable")
	}
	if completeLog.State != evidence.CompleteLogStateComplete || completeLog.Truncated || completeLog.Error != "" {
		return nil, 0, errors.New("complete log archive is incomplete")
	}
	if completeLog.ContentType != completeLogSourceContentType || completeLog.ContentEncoding != completeLogSourceEncoding {
		return nil, 0, errors.New("complete log archive encoding is invalid")
	}
	if completeLog.CompressedBytes < 0 || completeLog.CompressedBytes > maximumCompressedUploadBytes || completeLog.UncompressedBytes < 0 || completeLog.UncompressedBytes > evidence.MaximumCompleteLogBytes {
		return nil, 0, errors.New("complete log archive size is outside the supported bounds")
	}
	info, err := completeLog.Archive.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != completeLog.CompressedBytes {
		return nil, 0, errors.New("complete log archive size does not match its metadata")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.NewSectionReader(completeLog.Archive, 0, completeLog.CompressedBytes)); err != nil {
		return nil, 0, errors.New("complete log archive could not be hashed")
	}
	digestBytes := digest.Sum(nil)
	declared, err := hex.DecodeString(completeLog.SHA256)
	if err != nil || len(declared) != sha256.Size || !equalBytes(declared, digestBytes) {
		return nil, 0, errors.New("complete log archive digest does not match its metadata")
	}
	compressed := bufio.NewReader(io.NewSectionReader(completeLog.Archive, 0, completeLog.CompressedBytes))
	gzipReader, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, 0, errors.New("complete log archive is not valid gzip data")
	}
	gzipReader.Multistream(false)
	uncompressed, readErr := io.Copy(io.Discard, io.LimitReader(gzipReader, evidence.MaximumCompleteLogBytes+1))
	closeErr := gzipReader.Close()
	if readErr != nil || closeErr != nil || uncompressed > evidence.MaximumCompleteLogBytes || uncompressed != completeLog.UncompressedBytes {
		return nil, 0, errors.New("complete log archive contents do not match its metadata")
	}
	if _, err := compressed.Peek(1); !errors.Is(err, io.EOF) {
		return nil, 0, errors.New("complete log archive contains trailing data")
	}
	return digestBytes, completeLog.CompressedBytes, nil
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (r *countingReader) Read(data []byte) (int, error) {
	count, err := r.reader.Read(data)
	r.count += int64(count)
	return count, err
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
