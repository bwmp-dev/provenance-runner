//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// TestMeasuredStagingTreatsHostileJarsAsOpaqueBytes exercises the measured
// (hosted) input staging boundary with every hostile JAR fixture. Staging must
// copy exact bytes under a fixed alias, never inflate or interpret archive
// entries, and refuse any digest/size/alias mismatch without residue. The
// staging primitive requires real root and a root-owned 0700 directory, so the
// test runs only in the disposable privileged CI job (or a local root shell).
func TestMeasuredStagingTreatsHostileJarsAsOpaqueBytes(t *testing.T) {
	if os.Geteuid() != 0 || os.Getuid() != 0 {
		t.Skip("measured staging requires real root; runs in the disposable privileged gVisor job")
	}
	ctx := context.Background()
	for _, jar := range hostileJars(t) {
		t.Run(jar.name, func(t *testing.T) {
			if len(jar.content) == 0 {
				// Offer validation rejects zero-length downloads before staging.
				t.Skip("zero-size inputs are refused at offer admission")
			}
			inputs := filepath.Join(t.TempDir(), "inputs")
			if err := os.Mkdir(inputs, 0o700); err != nil {
				t.Fatal(err)
			}
			directory, err := os.Open(inputs)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			sourcePath := filepath.Join(t.TempDir(), "source.jar")
			if err := os.WriteFile(sourcePath, jar.content, 0o444); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			input := measuredInput{Name: "target.jar", Source: source, Size: uint64(len(jar.content)), SHA256: sha256.Sum256(jar.content)}
			wrongDigest, shortSize, traversal := input, input, input
			wrongDigest.SHA256[0] ^= 0xff
			shortSize.Size--
			traversal.Name = "../target.jar"
			for _, refused := range [][]measuredInput{{wrongDigest}, {shortSize}, {traversal}, {input, input}} {
				if stageMeasuredInputs(ctx, directory, refused, 1<<30) == nil {
					t.Fatal("hostile inventory admitted")
				}
				if entries, err := os.ReadDir(inputs); err != nil || len(entries) != 0 {
					t.Fatal("refused staging left residue")
				}
			}
			if err := stageMeasuredInputs(ctx, directory, []measuredInput{input}, 1<<30); err != nil {
				t.Fatalf("exact hostile bytes refused: %v", err)
			}
			entries, err := os.ReadDir(inputs)
			if err != nil || len(entries) != 1 || entries[0].Name() != "target.jar" {
				t.Fatalf("staged entries = %v, %v", entries, err)
			}
			staged, err := os.ReadFile(filepath.Join(inputs, "target.jar"))
			if err != nil || !bytes.Equal(staged, jar.content) {
				t.Fatal("staged bytes differ from the verified source")
			}
		})
	}
}
