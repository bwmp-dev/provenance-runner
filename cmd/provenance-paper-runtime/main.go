package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	return runWithPaperclip(ctx, arguments, stdout, stderr, paper.AlphaCatalog().Paper.Artifact, preparePaperclip)
}

type paperclipPreparer func(context.Context, string, string, string, io.Writer) error

func runWithPaperclip(ctx context.Context, arguments []string, stdout, stderr io.Writer, pin paper.ArtifactPin, prepare paperclipPreparer) error {
	flags := flag.NewFlagSet("provenance-paper-runtime", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var paperPath string
	var javaPath string
	var outputPath string
	flags.StringVar(&paperPath, "paper", "", "path to the pinned Paper alpha JAR")
	flags.StringVar(&javaPath, "java", "java", "path to a Java 21 or newer executable")
	flags.StringVar(&outputPath, "output", "paper-prepared-runtime.tar.gz", "new archive path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if paperPath == "" {
		return errors.New("-paper is required")
	}
	absoluteOutput, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	if _, err := os.Lstat(absoluteOutput); err == nil {
		return fmt.Errorf("output path %q already exists", absoluteOutput)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output path: %w", err)
	}
	stage, err := os.MkdirTemp("", "provenance-paper-runtime-")
	if err != nil {
		return fmt.Errorf("create preparation directory: %w", err)
	}
	defer os.RemoveAll(stage)
	stagedPaper := filepath.Join(stage, "paper.jar")
	if err := stageVerifiedPaper(ctx, paperPath, stagedPaper, pin); err != nil {
		return err
	}
	if prepare == nil {
		return errors.New("prepare offline Paper runtime: command runner is nil")
	}
	if err := prepare(ctx, javaPath, stagedPaper, stage, stderr); err != nil {
		return fmt.Errorf("prepare offline Paper runtime: %w", err)
	}

	temporary, err := os.CreateTemp(filepath.Dir(absoluteOutput), ".paper-runtime-*.tar.gz")
	if err != nil {
		return fmt.Errorf("create temporary archive: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	metadata, buildErr := paper.WritePreparedRuntimeArchive(ctx, stage, temporary)
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if err := errors.Join(buildErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Chmod(temporaryPath, 0o444); err != nil {
		return fmt.Errorf("make prepared runtime read-only: %w", err)
	}
	if err := os.Link(temporaryPath, absoluteOutput); err != nil {
		return fmt.Errorf("publish prepared runtime: %w", err)
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encode prepared runtime metadata: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, string(metadataJSON)); err != nil {
		return fmt.Errorf("write prepared runtime metadata: %w", err)
	}
	return nil
}

func stageVerifiedPaper(ctx context.Context, sourcePath, destinationPath string, pin paper.ArtifactPin) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open Paper JAR: %w", err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("inspect Paper JAR: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != pin.SizeBytes {
		return fmt.Errorf("Paper JAR must be the %d-byte alpha artifact", pin.SizeBytes)
	}
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create staged Paper JAR: %w", err)
	}
	keepDestination := false
	defer func() {
		if !keepDestination {
			_ = os.Remove(destinationPath)
		}
	}()
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, hasher), &contextReader{ctx: ctx, reader: source})
	if copyErr != nil {
		return errors.Join(fmt.Errorf("stage Paper JAR: %w", copyErr), destination.Close())
	}
	if written != pin.SizeBytes {
		return errors.Join(fmt.Errorf("Paper JAR changed size while staging: received %d bytes, want %d", written, pin.SizeBytes), destination.Close())
	}
	if digest := hex.EncodeToString(hasher.Sum(nil)); digest != pin.SHA256 {
		return errors.Join(fmt.Errorf("Paper JAR SHA-256 is %s, want %s", digest, pin.SHA256), destination.Close())
	}
	if err := destination.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync staged Paper JAR: %w", err), destination.Close())
	}
	if err := destination.Close(); err != nil {
		return fmt.Errorf("close staged Paper JAR: %w", err)
	}
	if err := os.Chmod(destinationPath, 0o400); err != nil {
		return fmt.Errorf("make staged Paper JAR read-only: %w", err)
	}
	keepDestination = true
	return nil
}

func preparePaperclip(ctx context.Context, javaPath, paperPath, stage string, stderr io.Writer) error {
	resolvedJava, err := exec.LookPath(javaPath)
	if err != nil {
		return fmt.Errorf("resolve Java executable: %w", err)
	}
	command := exec.CommandContext(ctx, resolvedJava, "-Dpaperclip.patchonly=true", "-jar", paperPath)
	command.Dir = stage
	command.Stdout = stderr
	command.Stderr = stderr
	return command.Run()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(content []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(content)
}
