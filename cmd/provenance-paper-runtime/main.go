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
	if err := verifyAlphaPaper(paperPath); err != nil {
		return err
	}
	resolvedJava, err := exec.LookPath(javaPath)
	if err != nil {
		return fmt.Errorf("resolve Java executable: %w", err)
	}
	stage, err := os.MkdirTemp("", "provenance-paper-runtime-")
	if err != nil {
		return fmt.Errorf("create preparation directory: %w", err)
	}
	defer os.RemoveAll(stage)
	absolutePaper, err := filepath.Abs(paperPath)
	if err != nil {
		return fmt.Errorf("resolve Paper JAR: %w", err)
	}
	command := exec.CommandContext(ctx, resolvedJava, "-Dpaperclip.patchonly=true", "-jar", absolutePaper)
	command.Dir = stage
	command.Stdout = stderr
	command.Stderr = stderr
	if err := command.Run(); err != nil {
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

func verifyAlphaPaper(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Paper JAR: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect Paper JAR: %w", err)
	}
	catalog := paper.AlphaCatalog()
	if !info.Mode().IsRegular() || info.Size() != catalog.Paper.Artifact.SizeBytes {
		return fmt.Errorf("Paper JAR must be the %d-byte alpha artifact", catalog.Paper.Artifact.SizeBytes)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("hash Paper JAR: %w", err)
	}
	if digest := hex.EncodeToString(hasher.Sum(nil)); digest != catalog.Paper.Artifact.SHA256 {
		return fmt.Errorf("Paper JAR SHA-256 is %s, want %s", digest, catalog.Paper.Artifact.SHA256)
	}
	return nil
}
