package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/provider/paper"
)

func TestRunRefusesToOverwriteOutputBeforePreparation(t *testing.T) {
	output := filepath.Join(t.TempDir(), "runtime.tar.gz")
	if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), []string{"-paper", "missing.jar", "-output", output}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("run() error = %v", err)
	}
	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "keep" {
		t.Fatalf("output content = %q, want unchanged", content)
	}
}

func TestRunExecutesOnlyStagedVerifiedPaper(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "paper.jar")
	output := filepath.Join(root, "runtime.tar.gz")
	verified := []byte("verified Paper bytes")
	if err := os.WriteFile(input, verified, 0o600); err != nil {
		t.Fatal(err)
	}
	pin := testPaperPin(verified)
	preparer := func(_ context.Context, _, stagedPaper, stage string, _ io.Writer) error {
		if err := os.WriteFile(input, []byte("replacement"), 0o600); err != nil {
			return err
		}
		staged, err := os.ReadFile(stagedPaper)
		if err != nil {
			return err
		}
		if !bytes.Equal(staged, verified) {
			return fmt.Errorf("staged Paper bytes = %q, want %q", staged, verified)
		}
		outputs := map[string]string{
			"cache/mojang_1.21.8.jar":          "mojang",
			"libraries/example/library.jar":    "library",
			"versions/1.21.8/paper-1.21.8.jar": "patched",
		}
		for name, content := range outputs {
			path := filepath.Join(stage, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	var stdout bytes.Buffer
	if err := runWithPaperclip(context.Background(), []string{"-paper", input, "-output", output}, &stdout, &bytes.Buffer{}, pin, preparer); err != nil {
		t.Fatalf("runWithPaperclip() error = %v", err)
	}
	var metadata paper.PreparedRuntimeMetadata
	if err := json.Unmarshal(stdout.Bytes(), &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	archive, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SHA256 != digest(archive) || metadata.SizeBytes != int64(len(archive)) || metadata.MaximumExpandedBytes != int64(len("mojanglibrarypatched")) {
		t.Fatalf("metadata = %#v", metadata)
	}
	if replaced, err := os.ReadFile(input); err != nil || string(replaced) != "replacement" {
		t.Fatalf("original input replacement = %q, %v", replaced, err)
	}
	if bytes.Contains(archive, []byte("replacement")) {
		t.Fatal("archive contains replacement input bytes")
	}
}

func TestStageVerifiedPaperRemovesWrongBytes(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input.jar")
	staged := filepath.Join(root, "staged.jar")
	if err := os.WriteFile(input, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin := testPaperPin([]byte("right"))
	if err := stageVerifiedPaper(context.Background(), input, staged, pin); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("stageVerifiedPaper() error = %v", err)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("invalid staged input remains executable: %v", err)
	}
}

func testPaperPin(content []byte) paper.ArtifactPin {
	return paper.ArtifactPin{SHA256: digest(content), SizeBytes: int64(len(content))}
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
