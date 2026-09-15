//go:build linux

package gvisor

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// Retain the staging negatives independently of the actual prepared bundle.
// This helper is called only inside the explicit disposable measured fixture.
func measuredFixtureInput(t *testing.T, ctx context.Context) (measuredInput, string) {
	t.Helper()
	inputs := filepath.Join(t.TempDir(), "inputs")
	if os.Mkdir(inputs, 0700) != nil {
		t.Fatal("private fixture input directory")
	}
	directory, err := os.Open(inputs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { directory.Close() })
	sourcePath := filepath.Join(t.TempDir(), "source")
	payload := []byte("synthetic-input")
	if os.WriteFile(sourcePath, payload, 0444) != nil {
		t.Fatal("synthetic source unavailable")
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	input := measuredInput{Name: "sample", Source: source, Size: uint64(len(payload)), SHA256: sha256.Sum256(payload)}
	badHash := input
	badHash.SHA256 = sha256.Sum256([]byte("wrong"))
	badName := input
	badName.Name = "../foreign"
	badSize := input
	badSize.Size++
	writable, err := os.OpenFile(sourcePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writable.Close() })
	badWritable := input
	badWritable.Source = writable
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pipeRead.Close(); pipeWrite.Close() })
	badPipe := input
	badPipe.Source = pipeRead
	for _, rejected := range [][]measuredInput{{badHash}, {badName}, {badSize}, {input, input}, {badWritable}, {badPipe}} {
		if stageMeasuredInputs(ctx, directory, rejected, 2<<20) == nil {
			t.Fatal("invalid input inventory admitted")
		}
		entries, err := os.ReadDir(inputs)
		if err != nil || len(entries) != 0 {
			t.Fatal("refused staging left partial files")
		}
	}
	if stageMeasuredInputs(ctx, directory, []measuredInput{input}, input.Size-1) == nil {
		t.Fatal("aggregate input quota bypassed")
	}
	foreign := filepath.Join(inputs, "foreign")
	if os.WriteFile(foreign, []byte("preserve"), 0600) != nil {
		t.Fatal("foreign fixture")
	}
	if stageMeasuredInputs(ctx, directory, []measuredInput{input}, 2<<20) == nil {
		t.Fatal("nonempty directory adopted")
	}
	if raw, err := os.ReadFile(foreign); err != nil || string(raw) != "preserve" {
		t.Fatal("foreign input changed")
	}
	if os.Remove(foreign) != nil {
		t.Fatal("exact foreign fixture cleanup")
	}
	if stageMeasuredInputs(ctx, directory, []measuredInput{input}, 2<<20) != nil {
		t.Fatal("verified staging refused")
	}
	if stageMeasuredInputs(ctx, directory, []measuredInput{input}, 2<<20) == nil {
		t.Fatal("sealed inputs reopened")
	}
	return input, sourcePath
}
