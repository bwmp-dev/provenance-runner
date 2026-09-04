package gatewayclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

const (
	restartEvidenceSchemaVersion = "provenance.runner-restart-evidence/v1alpha1"
	restartEvidenceDirectoryMode = 0o700
	restartEvidenceFileMode      = 0o600
	restartEvidenceQueueDepth    = 256
	maximumRestartMetadataBytes  = 64 << 10
)

type restartEvidenceIdentity struct {
	LeaseID            string `json:"leaseId"`
	JobID              string `json:"jobId"`
	ExecutionID        string `json:"executionId"`
	AttemptID          string `json:"attemptId"`
	AttemptNumber      uint32 `json:"attemptNumber"`
	ReleaseCandidateID string `json:"releaseCandidateId"`
	MatrixEntryID      string `json:"matrixEntryId"`
	BindingSHA256      string `json:"bindingSha256"`
}

type restartEvidenceMetadata struct {
	SchemaVersion string                  `json:"schemaVersion"`
	Identity      restartEvidenceIdentity `json:"identity"`
	StdoutBytes   int64                   `json:"stdoutBytes"`
	StderrBytes   int64                   `json:"stderrBytes"`
	StdoutSHA256  string                  `json:"stdoutSha256"`
	StderrSHA256  string                  `json:"stderrSha256"`
	StdoutLast    byte                    `json:"stdoutLast,omitempty"`
	StderrLast    byte                    `json:"stderrLast,omitempty"`
	Usage         execution.ResourceUsage `json:"usage"`
	UsageObserved bool                    `json:"usageObserved"`
	Failure       string                  `json:"failure,omitempty"`
}

type restartEvidenceCommand struct {
	stream string
	data   []byte
	usage  *execution.ResourceUsage
	done   chan error
}

type restartEvidenceStore struct {
	directory    string
	metadataPath string
	stdoutPath   string
	stderrPath   string

	commands chan restartEvidenceCommand
	done     chan struct{}
	closing  sync.RWMutex
	closed   bool
	overflow atomic.Bool

	mu       sync.Mutex
	metadata restartEvidenceMetadata
	err      error
	stdout   hash.Hash
	stderr   hash.Hash
}

type recoveredRestartEvidence struct {
	CompleteLog *execution.CompleteLog
	Usage       *runnerv1.ResourceUsage
	Identity    restartEvidenceIdentity
}

func (client *Client) beginRestartEvidence(lease *runnerv1.LeaseIdentity, attempt *runnerv1.AttemptIdentity) error {
	if client == nil || client.config.journalFile == "" {
		return nil
	}
	client.restartEvidenceMu.Lock()
	defer client.restartEvidenceMu.Unlock()
	if client.restartEvidence != nil {
		return errors.New("restart evidence already exists")
	}
	store, err := createRestartEvidenceStore(client.config.journalFile, lease, attempt)
	if err != nil {
		return err
	}
	client.restartEvidence = store
	return nil
}

func (client *Client) activeRestartEvidence() *restartEvidenceStore {
	if client == nil {
		return nil
	}
	client.restartEvidenceMu.Lock()
	defer client.restartEvidenceMu.Unlock()
	return client.restartEvidence
}

func (client *Client) clearRestartEvidence() error {
	if client == nil {
		return nil
	}
	client.restartEvidenceMu.Lock()
	store := client.restartEvidence
	client.restartEvidence = nil
	client.restartEvidenceMu.Unlock()
	if store == nil {
		return nil
	}
	closeErr := store.close()
	removeErr := removeRestartEvidenceDirectory(store.directory)
	return errors.Join(closeErr, removeErr)
}

func restartEvidencePath(journalPath string) string {
	if journalPath == "" {
		return ""
	}
	return journalPath + ".restart-evidence"
}

func openRestartEvidenceStore(journalPath string, active *journalJob) (*restartEvidenceStore, error) {
	directory := restartEvidencePath(journalPath)
	if directory == "" {
		return nil, nil
	}
	if active == nil {
		if err := removeRestartEvidenceDirectory(directory); err != nil {
			return nil, fmt.Errorf("remove acknowledged restart evidence: %w", err)
		}
		return nil, nil
	}
	lease, attempt, err := activeIdentity(journalState{Active: active})
	if err != nil {
		return nil, fmt.Errorf("resolve restart evidence identity: %w", err)
	}
	store, err := loadRestartEvidenceStore(directory, lease, attempt)
	if err != nil {
		return nil, fmt.Errorf("recover restart evidence: %w", err)
	}
	store.start()
	return store, nil
}

func createRestartEvidenceStore(journalPath string, lease *runnerv1.LeaseIdentity, attempt *runnerv1.AttemptIdentity) (*restartEvidenceStore, error) {
	directory := restartEvidencePath(journalPath)
	if directory == "" {
		return nil, nil
	}
	identity, err := newRestartEvidenceIdentity(lease, attempt)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(directory, restartEvidenceDirectoryMode); err != nil {
		return nil, fmt.Errorf("create restart evidence directory: %w", err)
	}
	if err := syncRestartEvidenceDirectory(filepath.Dir(directory)); err != nil {
		return nil, fmt.Errorf("sync restart evidence parent directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = removeRestartEvidenceDirectory(directory)
		}
	}()
	for _, path := range []string{filepath.Join(directory, "stdout"), filepath.Join(directory, "stderr")} {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, restartEvidenceFileMode)
		if err != nil {
			return nil, fmt.Errorf("create restart evidence source: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("sync restart evidence source: %w", err)
		}
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close restart evidence source: %w", err)
		}
	}
	store := newRestartEvidenceStore(directory, restartEvidenceMetadata{
		SchemaVersion: restartEvidenceSchemaVersion,
		Identity:      identity,
		StdoutSHA256:  emptySHA256(),
		StderrSHA256:  emptySHA256(),
	})
	if err := store.persistMetadata(); err != nil {
		return nil, err
	}
	if err := syncRestartEvidenceDirectory(directory); err != nil {
		return nil, fmt.Errorf("sync restart evidence directory: %w", err)
	}
	cleanup = false
	store.start()
	return store, nil
}

func loadRestartEvidenceStore(directory string, lease *runnerv1.LeaseIdentity, attempt *runnerv1.AttemptIdentity) (*restartEvidenceStore, error) {
	if err := validatePrivateDirectory(directory); err != nil {
		return nil, err
	}
	metadataPath := filepath.Join(directory, "metadata.json")
	data, err := readRegularFile(metadataPath, maximumRestartMetadataBytes, true)
	if err != nil {
		return nil, fmt.Errorf("read restart evidence metadata: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var metadata restartEvidenceMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decode restart evidence metadata: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode restart evidence metadata: multiple JSON values are not allowed")
	}
	expected, err := newRestartEvidenceIdentity(lease, attempt)
	if err != nil {
		return nil, err
	}
	if metadata.SchemaVersion != restartEvidenceSchemaVersion || metadata.Identity != expected {
		return nil, errors.New("restart evidence identity or schema does not match the active attempt")
	}
	store := newRestartEvidenceStore(directory, metadata)
	if err := store.validateSources(); err != nil {
		return nil, err
	}
	store.stdout, err = hashRestartEvidenceSource(store.stdoutPath, metadata.StdoutBytes)
	if err != nil {
		return nil, err
	}
	store.stderr, err = hashRestartEvidenceSource(store.stderrPath, metadata.StderrBytes)
	if err != nil {
		return nil, err
	}
	if metadata.Failure != "" {
		store.err = errors.New(metadata.Failure)
	}
	return store, nil
}

func newRestartEvidenceStore(directory string, metadata restartEvidenceMetadata) *restartEvidenceStore {
	return &restartEvidenceStore{
		directory: directory, metadataPath: filepath.Join(directory, "metadata.json"),
		stdoutPath: filepath.Join(directory, "stdout"), stderrPath: filepath.Join(directory, "stderr"),
		commands: make(chan restartEvidenceCommand, restartEvidenceQueueDepth), done: make(chan struct{}),
		metadata: metadata, stdout: sha256.New(), stderr: sha256.New(),
	}
}

func (store *restartEvidenceStore) start() {
	go store.run()
}

func (store *restartEvidenceStore) run() {
	defer close(store.done)
	for command := range store.commands {
		err := store.apply(command)
		if command.done != nil {
			command.done <- err
		}
	}
	store.mu.Lock()
	if store.overflow.Load() && store.err == nil {
		store.failLocked(errors.New("restart evidence queue overflowed"))
	}
	store.mu.Unlock()
}

func (store *restartEvidenceStore) apply(command restartEvidenceCommand) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.overflow.Load() && store.err == nil {
		store.failLocked(errors.New("restart evidence queue overflowed"))
	}
	if store.err != nil {
		return store.err
	}
	var err error
	switch {
	case len(command.data) != 0:
		err = store.appendLocked(command.stream, command.data)
	case command.usage != nil:
		if command.usage.CPUTime < 0 {
			err = errors.New("restart evidence usage is invalid")
			break
		}
		mergeResourceUsage(&store.metadata.Usage, *command.usage)
		store.metadata.UsageObserved = true
		err = store.persistMetadata()
	case command.done != nil:
		return nil
	default:
		err = errors.New("restart evidence command is empty")
	}
	if err != nil {
		store.failLocked(err)
	}
	return store.err
}

func (store *restartEvidenceStore) appendLocked(stream string, data []byte) error {
	path := store.stdoutPath
	currentBytes := store.metadata.StdoutBytes
	if stream == "stderr" {
		path = store.stderrPath
		currentBytes = store.metadata.StderrBytes
	} else if stream != "stdout" {
		return errors.New("restart evidence stream is invalid")
	}
	if int64(len(data)) > evidence.MaximumCompleteLogBytes-currentBytes || !restartEvidenceWithinBound(store.metadata, stream, data) {
		return fmt.Errorf("restart complete log exceeded the %d-byte retention boundary", evidence.MaximumCompleteLogBytes)
	}
	file, err := openRestartEvidenceAppend(path, currentBytes)
	if err != nil {
		return fmt.Errorf("open restart evidence source: %w", err)
	}
	written, writeErr := writeRestartEvidence(file, data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(data) {
		return fmt.Errorf("append restart evidence source: %w", errors.Join(writeErr, syncErr, closeErr))
	}
	if stream == "stdout" {
		store.metadata.StdoutBytes += int64(written)
		store.metadata.StdoutLast = data[len(data)-1]
		_, _ = store.stdout.Write(data)
		store.metadata.StdoutSHA256 = hex.EncodeToString(store.stdout.Sum(nil))
	} else {
		store.metadata.StderrBytes += int64(written)
		store.metadata.StderrLast = data[len(data)-1]
		_, _ = store.stderr.Write(data)
		store.metadata.StderrSHA256 = hex.EncodeToString(store.stderr.Sum(nil))
	}
	return store.persistMetadata()
}

func openRestartEvidenceAppend(path string, size int64) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || !privateFileMode(pathInfo.Mode().Perm()) || pathInfo.Size() != size {
		return nil, errors.New("restart evidence source is missing, substituted, or has unsafe permissions")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, restartEvidenceFileMode)
	if err != nil {
		return nil, err
	}
	fileInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, fileInfo) || !fileInfo.Mode().IsRegular() || !privateFileMode(fileInfo.Mode().Perm()) || fileInfo.Size() != size {
		_ = file.Close()
		return nil, errors.New("restart evidence source changed while opening")
	}
	return file, nil
}

func restartEvidenceWithinBound(metadata restartEvidenceMetadata, stream string, data []byte) bool {
	stdoutBytes, stderrBytes := metadata.StdoutBytes, metadata.StderrBytes
	stdoutLast, stderrLast := metadata.StdoutLast, metadata.StderrLast
	if stream == "stdout" {
		stdoutBytes += int64(len(data))
		stdoutLast = data[len(data)-1]
	} else {
		stderrBytes += int64(len(data))
		stderrLast = data[len(data)-1]
	}
	return completeLogUncompressedBytes(stdoutBytes, stderrBytes, stdoutLast, stderrLast) <= evidence.MaximumCompleteLogBytes
}

func completeLogUncompressedBytes(stdoutBytes, stderrBytes int64, stdoutLast, stderrLast byte) int64 {
	var size int64
	if stdoutBytes > 0 {
		size += int64(len("[stdout]\n")) + stdoutBytes
		if stdoutLast != '\n' {
			size++
		}
	}
	if stderrBytes > 0 {
		size += int64(len("[stderr]\n")) + stderrBytes
		if stderrLast != '\n' {
			size++
		}
	}
	return size
}

func (store *restartEvidenceStore) failLocked(err error) {
	if err == nil || store.err != nil {
		return
	}
	store.err = err
	store.metadata.Failure = boundedSummary(err.Error())
	_ = store.persistMetadata()
}

func (store *restartEvidenceStore) observeLog(entry execution.LiveLogEntry) {
	if store == nil || (entry.Stream != "stdout" && entry.Stream != "stderr") || len(entry.Data) == 0 {
		return
	}
	store.enqueue(restartEvidenceCommand{stream: entry.Stream, data: bytes.Clone(entry.Data)})
}

func (store *restartEvidenceStore) observeUsage(usage execution.ResourceUsage) {
	if store == nil {
		return
	}
	copyUsage := usage
	store.enqueue(restartEvidenceCommand{usage: &copyUsage})
}

func (store *restartEvidenceStore) enqueue(command restartEvidenceCommand) {
	store.closing.RLock()
	defer store.closing.RUnlock()
	if store.closed {
		store.overflow.Store(true)
		return
	}
	select {
	case store.commands <- command:
	default:
		store.overflow.Store(true)
	}
}

func (store *restartEvidenceStore) flush() error {
	if store == nil {
		return errors.New("restart evidence is unavailable")
	}
	done := make(chan error, 1)
	store.closing.RLock()
	if store.closed {
		store.closing.RUnlock()
		store.mu.Lock()
		defer store.mu.Unlock()
		return store.err
	}
	store.commands <- restartEvidenceCommand{done: done}
	store.closing.RUnlock()
	return <-done
}

func (store *restartEvidenceStore) close() error {
	if store == nil {
		return nil
	}
	store.closing.Lock()
	if !store.closed {
		store.closed = true
		close(store.commands)
	}
	store.closing.Unlock()
	<-store.done
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.err
}

func (store *restartEvidenceStore) snapshot(ctx context.Context) (recoveredRestartEvidence, error) {
	if err := store.flush(); err != nil {
		return recoveredRestartEvidence{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return recoveredRestartEvidence{}, err
	}
	if err := store.validateSources(); err != nil {
		store.failLocked(err)
		return recoveredRestartEvidence{}, err
	}
	if !store.metadata.UsageObserved || store.metadata.Usage.CPUTime < 0 {
		return recoveredRestartEvidence{}, errors.New("restart evidence cumulative usage is missing or invalid")
	}
	archive, err := secureRestartArchive()
	if err != nil {
		return recoveredRestartEvidence{}, err
	}
	digest := sha256.New()
	compressed := &restartEvidenceCountingWriter{writer: io.MultiWriter(archive, digest)}
	zipWriter := gzip.NewWriter(&restartEvidenceContextWriter{ctx: ctx, writer: compressed})
	uncompressed, writeErr := store.writeCompleteLog(zipWriter)
	closeErr := zipWriter.Close()
	syncErr := archive.Sync()
	if writeErr != nil || closeErr != nil || syncErr != nil {
		_ = archive.Close()
		return recoveredRestartEvidence{}, fmt.Errorf("finalize restart complete log: %w", errors.Join(writeErr, closeErr, syncErr))
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		_ = archive.Close()
		return recoveredRestartEvidence{}, fmt.Errorf("rewind restart complete log: %w", err)
	}
	completeLog := &execution.CompleteLog{
		State: "complete", ContentType: completeLogSourceContentType, ContentEncoding: completeLogSourceEncoding,
		SHA256: hex.EncodeToString(digest.Sum(nil)), UncompressedBytes: uncompressed, CompressedBytes: compressed.count, Archive: archive,
	}
	return recoveredRestartEvidence{CompleteLog: completeLog, Usage: resourceUsageMessage(store.metadata.Usage), Identity: store.metadata.Identity}, nil
}

func (store *restartEvidenceStore) writeCompleteLog(writer io.Writer) (int64, error) {
	var total int64
	for _, source := range []struct {
		name string
		path string
		size int64
		last byte
	}{{"stdout", store.stdoutPath, store.metadata.StdoutBytes, store.metadata.StdoutLast}, {"stderr", store.stderrPath, store.metadata.StderrBytes, store.metadata.StderrLast}} {
		if source.size == 0 {
			continue
		}
		file, err := os.Open(source.path)
		if err != nil {
			return total, err
		}
		header := []byte("[" + source.name + "]\n")
		written, err := writeRestartEvidence(writer, header)
		total += int64(written)
		if err == nil {
			var copied int64
			copied, err = io.CopyN(writer, file, source.size)
			total += copied
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return total, errors.Join(err, closeErr)
		}
		if source.last != '\n' {
			written, err = writeRestartEvidence(writer, []byte{'\n'})
			total += int64(written)
			if err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

func secureRestartArchive() (*os.File, error) {
	file, err := os.CreateTemp("", "provenance-restart-complete-*.gz")
	if err != nil {
		return nil, err
	}
	name := file.Name()
	if err := file.Chmod(restartEvidenceFileMode); err != nil {
		return nil, errors.Join(err, file.Close(), os.Remove(name))
	}
	if err := os.Remove(name); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func (store *restartEvidenceStore) validateSources() error {
	for _, source := range []struct {
		path   string
		size   int64
		digest string
		last   byte
	}{{store.stdoutPath, store.metadata.StdoutBytes, store.metadata.StdoutSHA256, store.metadata.StdoutLast}, {store.stderrPath, store.metadata.StderrBytes, store.metadata.StderrSHA256, store.metadata.StderrLast}} {
		if err := validateRestartEvidenceSource(source.path, source.size, source.digest, source.last); err != nil {
			return err
		}
	}
	if completeLogUncompressedBytes(store.metadata.StdoutBytes, store.metadata.StderrBytes, store.metadata.StdoutLast, store.metadata.StderrLast) > evidence.MaximumCompleteLogBytes {
		return errors.New("restart evidence exceeds the complete-log retention boundary")
	}
	return nil
}

func validateRestartEvidenceSource(path string, size int64, expectedDigest string, expectedLast byte) error {
	if size < 0 || size > evidence.MaximumCompleteLogBytes || len(expectedDigest) != sha256.Size*2 {
		return errors.New("restart evidence source metadata is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !privateFileMode(info.Mode().Perm()) || info.Size() != size {
		return errors.New("restart evidence source is missing, substituted, or has unsafe permissions")
	}
	digest, err := digestFile(path, size)
	if err != nil || digest != expectedDigest {
		return errors.New("restart evidence source digest does not match committed metadata")
	}
	if size == 0 {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	last := []byte{0}
	_, readErr := file.ReadAt(last, size-1)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || last[0] != expectedLast {
		return errors.New("restart evidence source terminal byte is invalid")
	}
	return nil
}

func digestFile(path string, size int64) (string, error) {
	digest, err := hashRestartEvidenceSource(path, size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func hashRestartEvidenceSource(path string, size int64) (hash.Hash, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	copied, copyErr := io.CopyN(digest, file, size)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || copied != size {
		return nil, errors.Join(copyErr, closeErr)
	}
	return digest, nil
}

func emptySHA256() string {
	digest := sha256.Sum256(nil)
	return hex.EncodeToString(digest[:])
}

func newRestartEvidenceIdentity(lease *runnerv1.LeaseIdentity, attempt *runnerv1.AttemptIdentity) (restartEvidenceIdentity, error) {
	if lease == nil || attempt == nil {
		return restartEvidenceIdentity{}, errors.New("restart evidence lease and attempt are required")
	}
	for field, value := range map[string]string{
		"leaseId": lease.GetLeaseId(), "jobId": lease.GetJobId(), "executionId": lease.GetExecutionId(),
		"attemptId": attempt.GetAttemptId(), "releaseCandidateId": attempt.GetReleaseCandidateId(), "matrixEntryId": attempt.GetMatrixEntryId(),
	} {
		if validateUUID(field, value) != nil {
			return restartEvidenceIdentity{}, errors.New("restart evidence identity is invalid")
		}
	}
	if attempt.GetAttemptNumber() == 0 || attempt.GetAttemptNumber() > maximumAttemptNumber {
		return restartEvidenceIdentity{}, errors.New("restart evidence attempt number is invalid")
	}
	identity := restartEvidenceIdentity{
		LeaseID: lease.GetLeaseId(), JobID: lease.GetJobId(), ExecutionID: lease.GetExecutionId(), AttemptID: attempt.GetAttemptId(),
		AttemptNumber: attempt.GetAttemptNumber(), ReleaseCandidateID: attempt.GetReleaseCandidateId(), MatrixEntryID: attempt.GetMatrixEntryId(),
	}
	identityBytes, err := json.Marshal(identity)
	if err != nil {
		return restartEvidenceIdentity{}, err
	}
	binding := sha256.New()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(identityBytes)))
	_, _ = binding.Write(length[:])
	_, _ = binding.Write(identityBytes)
	identity.BindingSHA256 = hex.EncodeToString(binding.Sum(nil))
	return identity, nil
}

func (store *restartEvidenceStore) persistMetadata() error {
	data, err := json.Marshal(store.metadata)
	if err != nil {
		return fmt.Errorf("encode restart evidence metadata: %w", err)
	}
	if len(data) > maximumRestartMetadataBytes {
		return errors.New("restart evidence metadata exceeds its size bound")
	}
	temporary, err := os.CreateTemp(store.directory, ".restart-evidence-metadata-*")
	if err != nil {
		return fmt.Errorf("create restart evidence metadata: %w", err)
	}
	name := temporary.Name()
	remove := true
	defer func() {
		_ = temporary.Close()
		if remove {
			_ = os.Remove(name)
		}
	}()
	if err := temporary.Chmod(restartEvidenceFileMode); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, store.metadataPath); err != nil {
		return fmt.Errorf("commit restart evidence metadata: %w", err)
	}
	remove = false
	return syncRestartEvidenceDirectory(store.directory)
}

type restartEvidenceCountingWriter struct {
	writer io.Writer
	count  int64
}

func (writer *restartEvidenceCountingWriter) Write(content []byte) (int, error) {
	written, err := writer.writer.Write(content)
	writer.count += int64(written)
	return written, err
}

type restartEvidenceContextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (writer *restartEvidenceContextWriter) Write(content []byte) (int, error) {
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	return writer.writer.Write(content)
}

func writeRestartEvidence(writer io.Writer, content []byte) (int, error) {
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

func syncRestartEvidenceDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validatePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("restart evidence directory is not an owner-only directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "metadata.json" || entry.Name() == "stdout" || entry.Name() == "stderr" {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".restart-evidence-metadata-") {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || !privateFileMode(info.Mode().Perm()) {
				return errors.New("restart evidence directory contains an unsafe temporary entry")
			}
			continue
		}
		return errors.New("restart evidence directory contains an unexpected entry")
	}
	return nil
}

func removeRestartEvidenceDirectory(directory string) error {
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := validatePrivateDirectory(directory); err != nil {
		return err
	}
	for _, name := range []string{"metadata.json", "stdout", "stderr"} {
		path := filepath.Join(directory, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".restart-evidence-metadata-") {
			continue
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
	}
	if err := os.Remove(directory); err != nil {
		return err
	}
	return syncRestartEvidenceDirectory(filepath.Dir(directory))
}
