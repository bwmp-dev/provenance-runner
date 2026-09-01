package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
)

const (
	completeLogContentType     = "text/plain; charset=utf-8"
	completeLogContentEncoding = "gzip"
	maximumCompleteLogBytes    = localjob.MaximumOutputBytes + int64(len("[stdout]\n")+len("[stderr]\n")+2)
	maximumCompressedLogBytes  = maximumCompleteLogBytes + (1 << 20)
)

func writeResultAndCompleteLog(stdout, stderr io.Writer, result execution.Result, completeLogPath string) int {
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
	return exportCompleteLogFile(path, completeLog.Data)
}

func validateCompleteLog(completeLog *execution.CompleteLog) error {
	if completeLog == nil || len(completeLog.Data) == 0 {
		return errors.New("complete log data is unavailable")
	}
	if completeLog.ContentType != completeLogContentType {
		return fmt.Errorf("unexpected content type %q", completeLog.ContentType)
	}
	if completeLog.ContentEncoding != completeLogContentEncoding {
		return fmt.Errorf("unexpected content encoding %q", completeLog.ContentEncoding)
	}
	if int64(len(completeLog.Data)) > maximumCompressedLogBytes {
		return fmt.Errorf("compressed data exceeds %d bytes", maximumCompressedLogBytes)
	}
	if completeLog.CompressedBytes != int64(len(completeLog.Data)) {
		return fmt.Errorf("compressed byte count is %d, expected %d", completeLog.CompressedBytes, len(completeLog.Data))
	}
	digest := sha256.Sum256(completeLog.Data)
	if completeLog.SHA256 != hex.EncodeToString(digest[:]) {
		return errors.New("SHA-256 metadata does not match complete log data")
	}
	if completeLog.UncompressedBytes < 0 || completeLog.UncompressedBytes > maximumCompleteLogBytes {
		return fmt.Errorf("uncompressed byte count is %d, expected between 0 and %d", completeLog.UncompressedBytes, maximumCompleteLogBytes)
	}
	compressed := bytes.NewReader(completeLog.Data)
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
	if compressed.Len() != 0 {
		return errors.New("gzip data contains trailing bytes or additional members")
	}
	if completeLog.UncompressedBytes != uncompressedBytes {
		return fmt.Errorf("uncompressed byte count is %d, expected %d", completeLog.UncompressedBytes, uncompressedBytes)
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if written > 0 {
			data = data[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func wrapCompleteLogError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
