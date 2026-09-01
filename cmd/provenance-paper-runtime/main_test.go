package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestVerifyAlphaPaperRejectsWrongArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "paper.jar")
	if err := os.WriteFile(path, []byte("not Paper"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyAlphaPaper(path); err == nil || !strings.Contains(err.Error(), "52811717-byte alpha artifact") {
		t.Fatalf("verifyAlphaPaper() error = %v", err)
	}
}
