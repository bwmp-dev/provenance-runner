package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

func TestValidateCompleteLogAcceptsExactBoundedGzip(t *testing.T) {
	completeLog := completeLogFromContent(t, []byte("validated complete log"))
	if err := validateCompleteLog(completeLog); err != nil {
		t.Fatalf("validateCompleteLog() error = %v", err)
	}
}

func TestValidateCompleteLogRejectsMalformedTruncatedAndMismatchedGzip(t *testing.T) {
	valid := completeLogFromContent(t, []byte("validated complete log"))
	secondMember := completeLogFromContent(t, []byte("second member"))
	tests := []struct {
		name    string
		data    []byte
		length  int64
		message string
	}{
		{name: "malformed", data: []byte("not gzip"), length: 8, message: "decode gzip data"},
		{name: "truncated", data: valid.Data[:len(valid.Data)-4], length: valid.UncompressedBytes, message: "decode gzip data"},
		{name: "uncompressed length", data: valid.Data, length: valid.UncompressedBytes + 1, message: "uncompressed byte count"},
		{name: "trailing bytes", data: append(append([]byte(nil), valid.Data...), 0), length: valid.UncompressedBytes, message: "trailing bytes or additional members"},
		{name: "additional member", data: append(append([]byte(nil), valid.Data...), secondMember.Data...), length: valid.UncompressedBytes, message: "trailing bytes or additional members"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			completeLog := completeLogFromCompressed(test.data, test.length)
			err := validateCompleteLog(completeLog)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("validateCompleteLog() error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestValidateCompleteLogBoundsDecompression(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := io.CopyN(writer, zeroReader{}, maximumCompleteLogBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	completeLog := completeLogFromCompressed(compressed.Bytes(), maximumCompleteLogBytes)
	err := validateCompleteLog(completeLog)
	if err == nil || !strings.Contains(err.Error(), "gzip data exceeds") {
		t.Fatalf("validateCompleteLog() error = %v", err)
	}
}

func completeLogFromContent(t *testing.T, content []byte) *execution.CompleteLog {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return completeLogFromCompressed(compressed.Bytes(), int64(len(content)))
}

func completeLogFromCompressed(data []byte, uncompressedBytes int64) *execution.CompleteLog {
	digest := sha256.Sum256(data)
	return &execution.CompleteLog{
		ContentType:       completeLogContentType,
		ContentEncoding:   completeLogContentEncoding,
		SHA256:            hex.EncodeToString(digest[:]),
		UncompressedBytes: uncompressedBytes,
		CompressedBytes:   int64(len(data)),
		Data:              append([]byte(nil), data...),
	}
}

type zeroReader struct{}

func (zeroReader) Read(data []byte) (int, error) {
	return len(data), nil
}
