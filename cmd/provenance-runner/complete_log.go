package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
)

const (
	completeLogContentType     = "text/plain; charset=utf-8"
	completeLogContentEncoding = "gzip"
	maximumCompleteLogBytes    = evidence.MaximumCompleteLogBytes
	maximumCompressedLogBytes  = maximumCompleteLogBytes + (1 << 20)
)

func writeResultAndCompleteLog(stdout, stderr io.Writer, result execution.Result, completeLogPath string) int {
	defer releaseCompleteLog(result.CompleteLog)
	exitCode := writeResult(stdout, result)
	if completeLogPath == "" {
		return exitCode
	}
	if err := exportCompleteLog(completeLogPath, result.CompleteLog); err != nil {
		fmt.Fprintf(stderr, "export complete log: %v\n", err)
		return 2
	}
	return exitCode
}

func exportCompleteLog(path string, completeLog *execution.CompleteLog) error {
	if err := validateCompleteLog(completeLog); err != nil {
		return err
	}
	return exportCompleteLogFile(path, io.NewSectionReader(completeLog.Archive, 0, completeLog.CompressedBytes))
}

func validateCompleteLog(completeLog *execution.CompleteLog) error {
	if completeLog == nil {
		return errors.New("complete log data is unavailable")
	}
	if completeLog.State != evidence.CompleteLogStateComplete || completeLog.Truncated {
		if completeLog.Error != "" {
			return fmt.Errorf("complete log archive state is %q: %s", completeLog.State, completeLog.Error)
		}
		return fmt.Errorf("complete log archive state is %q", completeLog.State)
	}
	if completeLog.Archive == nil {
		return errors.New("complete log data is unavailable")
	}
	if completeLog.ContentType != completeLogContentType {
		return fmt.Errorf("unexpected content type %q", completeLog.ContentType)
	}
	if completeLog.ContentEncoding != completeLogContentEncoding {
		return fmt.Errorf("unexpected content encoding %q", completeLog.ContentEncoding)
	}
	if completeLog.CompressedBytes < 0 || completeLog.CompressedBytes > maximumCompressedLogBytes {
		return fmt.Errorf("compressed data exceeds %d bytes", maximumCompressedLogBytes)
	}
	info, err := completeLog.Archive.Stat()
	if err != nil {
		return fmt.Errorf("inspect complete log archive: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != completeLog.CompressedBytes {
		return fmt.Errorf("compressed byte count is %d, archive contains %d", completeLog.CompressedBytes, info.Size())
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.NewSectionReader(completeLog.Archive, 0, completeLog.CompressedBytes)); err != nil {
		return fmt.Errorf("hash complete log archive: %w", err)
	}
	if completeLog.SHA256 != hex.EncodeToString(digest.Sum(nil)) {
		return errors.New("SHA-256 metadata does not match complete log data")
	}
	if completeLog.UncompressedBytes < 0 || completeLog.UncompressedBytes > maximumCompleteLogBytes {
		return fmt.Errorf("uncompressed byte count is %d, expected between 0 and %d", completeLog.UncompressedBytes, maximumCompleteLogBytes)
	}
	compressed := bufio.NewReader(io.NewSectionReader(completeLog.Archive, 0, completeLog.CompressedBytes))
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		return fmt.Errorf("decode gzip data: %w", err)
	}
	reader.Multistream(false)
	uncompressedBytes, readErr := io.Copy(io.Discard, io.LimitReader(reader, maximumCompleteLogBytes+1))
	closeErr := reader.Close()
	if readErr != nil {
		return fmt.Errorf("decode gzip data: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close gzip data: %w", closeErr)
	}
	if uncompressedBytes > maximumCompleteLogBytes {
		return fmt.Errorf("gzip data exceeds %d uncompressed bytes", maximumCompleteLogBytes)
	}
	if _, err := compressed.Peek(1); !errors.Is(err, io.EOF) {
		return errors.New("gzip data contains trailing bytes or additional members")
	}
	if completeLog.UncompressedBytes != uncompressedBytes {
		return fmt.Errorf("uncompressed byte count is %d, expected %d", completeLog.UncompressedBytes, uncompressedBytes)
	}
	return nil
}

func releaseCompleteLog(completeLog *execution.CompleteLog) {
	if completeLog == nil || completeLog.Archive == nil {
		return
	}
	_ = completeLog.Archive.Close()
	completeLog.Archive = nil
}

func wrapCompleteLogError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
