package evidence

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	CompleteLogStateComplete  = "complete"
	CompleteLogStateTruncated = "truncated"
	CompleteLogStateFailed    = "failed"
	completeLogOverhead       = int64(len("[stdout]\n") + len("[stderr]\n") + 2)
)

type archiveSpool struct {
	stdout      *os.File
	stderr      *os.File
	maximum     int64
	spooled     int64
	stdoutBytes int64
	stderrBytes int64
	state       string
	failure     string
}

func newArchiveSpool(maximum int64) (*archiveSpool, error) {
	stdout, err := secureTemporaryFile("provenance-complete-stdout-*")
	if err != nil {
		return nil, fmt.Errorf("create complete-log stdout spool: %w", err)
	}
	stderr, err := secureTemporaryFile("provenance-complete-stderr-*")
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create complete-log stderr spool: %w", err), stdout.Close())
	}
	return &archiveSpool{stdout: stdout, stderr: stderr, maximum: maximum}, nil
}

func secureTemporaryFile(pattern string) (*os.File, error) {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, err
	}
	name := file.Name()
	if err := file.Chmod(0o600); err != nil {
		return nil, errors.Join(err, file.Close(), os.Remove(name))
	}
	// The runner is Linux-only for hosted execution. Removing the directory
	// entry immediately prevents other processes from racing or reopening the
	// secret-bearing normalized spool while this descriptor remains live.
	if err := os.Remove(name); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func (s *archiveSpool) append(stream Stream, content []byte) {
	if s.state != "" || len(content) == 0 {
		return
	}
	if int64(len(content)) > s.maximum-completeLogOverhead-s.spooled {
		s.state = CompleteLogStateTruncated
		s.failure = fmt.Sprintf("complete log exceeded the %d-byte operational retention boundary", s.maximum)
		s.discardSources()
		return
	}
	file := s.stdout
	if stream == StreamStderr {
		file = s.stderr
	}
	written, err := writeArchive(file, content)
	s.spooled += int64(written)
	if stream == StreamStdout {
		s.stdoutBytes += int64(written)
	} else {
		s.stderrBytes += int64(written)
	}
	if err != nil {
		s.state = CompleteLogStateFailed
		s.failure = fmt.Sprintf("spool complete log: %v", err)
		s.discardSources()
	}
}

func writeArchive(writer io.Writer, content []byte) (int, error) {
	total := 0
	for len(content) > 0 {
		written, err := writer.Write(content)
		total += written
		content = content[written:]
		if err != nil {
			return total, err
		}
		if written == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (s *archiveSpool) finalize(ctx context.Context) (CompleteLog, error) {
	if s.state != "" {
		return s.unavailable(), errors.New(s.failure)
	}
	archive, err := secureTemporaryFile("provenance-complete-archive-*.gz")
	if err != nil {
		s.fail(fmt.Errorf("create compressed complete-log spool: %w", err))
		return s.unavailable(), errors.New(s.failure)
	}

	digest := sha256.New()
	compressed := &countingWriter{writer: io.MultiWriter(archive, digest)}
	zipWriter := gzip.NewWriter(&contextWriter{ctx: ctx, writer: compressed})
	uncompressed, writeErr := s.writeCompleteLog(zipWriter)
	closeErr := zipWriter.Close()
	syncErr := archive.Sync()
	if writeErr != nil || closeErr != nil || syncErr != nil {
		failure := errors.Join(writeErr, closeErr, syncErr)
		_ = archive.Close()
		s.fail(fmt.Errorf("compress complete log: %w", failure))
		return s.unavailable(), errors.New(s.failure)
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		_ = archive.Close()
		s.fail(fmt.Errorf("rewind compressed complete log: %w", err))
		return s.unavailable(), errors.New(s.failure)
	}
	s.discardSources()
	return CompleteLog{
		State:             CompleteLogStateComplete,
		ContentType:       "text/plain; charset=utf-8",
		ContentEncoding:   "gzip",
		SHA256:            hex.EncodeToString(digest.Sum(nil)),
		UncompressedBytes: uncompressed,
		CompressedBytes:   compressed.count,
		Archive:           archive,
	}, nil
}

func (s *archiveSpool) writeCompleteLog(writer io.Writer) (int64, error) {
	var total int64
	for _, stream := range []struct {
		name  string
		file  *os.File
		bytes int64
	}{
		{name: string(StreamStdout), file: s.stdout, bytes: s.stdoutBytes},
		{name: string(StreamStderr), file: s.stderr, bytes: s.stderrBytes},
	} {
		if stream.bytes == 0 {
			continue
		}
		if err := stream.file.Sync(); err != nil {
			return total, err
		}
		if _, err := stream.file.Seek(0, io.SeekStart); err != nil {
			return total, err
		}
		header := []byte("[" + stream.name + "]\n")
		written, err := writeArchive(writer, header)
		total += int64(written)
		if err != nil {
			return total, err
		}
		copied, err := io.CopyN(writer, stream.file, stream.bytes)
		total += copied
		if err != nil {
			return total, err
		}
		last := []byte{0}
		if _, err := stream.file.ReadAt(last, stream.bytes-1); err != nil {
			return total, err
		}
		if last[0] != '\n' {
			written, err := writeArchive(writer, []byte{'\n'})
			total += int64(written)
			if err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

func (s *archiveSpool) fail(err error) {
	s.state = CompleteLogStateFailed
	s.failure = err.Error()
	s.discardSources()
}

func (s *archiveSpool) unavailable() CompleteLog {
	state := s.state
	if state == "" {
		state = CompleteLogStateFailed
	}
	return CompleteLog{State: state, Truncated: state == CompleteLogStateTruncated, Error: s.failure}
}

func (s *archiveSpool) discardSources() {
	if s.stdout != nil {
		_ = s.stdout.Close()
		s.stdout = nil
	}
	if s.stderr != nil {
		_ = s.stderr.Close()
		s.stderr = nil
	}
}

type countingWriter struct {
	writer io.Writer
	count  int64
}

func (w *countingWriter) Write(content []byte) (int, error) {
	written, err := w.writer.Write(content)
	w.count += int64(written)
	return written, err
}
