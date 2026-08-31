package gvisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type bundleMetadata struct {
	Version     int    `json:"version"`
	ContainerID string `json:"containerId"`
	Phase       string `json:"phase"`
}

func (p *Provider) Reconcile(ctx context.Context) error {
	entries, err := os.ReadDir(p.config.BundleRoot)
	if err != nil {
		return fmt.Errorf("reconcile gVisor bundles: %w", err)
	}
	var reconciliationErrors []error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		bundle := filepath.Join(p.config.BundleRoot, entry.Name())
		metadata, err := readMetadata(filepath.Join(bundle, metadataName))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			reconciliationErrors = append(reconciliationErrors, fmt.Errorf("inspect bundle %q: %w", entry.Name(), err))
			continue
		}
		if metadata.Version != metadataVersion || metadata.Phase != metadataPhasePrepared || !validContainerID(metadata.ContainerID) {
			reconciliationErrors = append(reconciliationErrors, fmt.Errorf("inspect bundle %q: invalid ownership metadata", entry.Name()))
			continue
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(append(reconciliationErrors, err)...)
		}
		attempted, err := runWasAttempted(bundle)
		if err != nil {
			reconciliationErrors = append(reconciliationErrors, fmt.Errorf("inspect bundle %q run-attempt state: %w", entry.Name(), err))
			continue
		}
		if !attempted {
			if err := removeOwnedBundle(p.config.BundleRoot, bundle); err != nil {
				reconciliationErrors = append(reconciliationErrors, err)
			}
			continue
		}
		result := p.runner.Run(ctx, command{
			Path: p.config.RunscPath,
			Args: p.runArguments("delete", "--force", metadata.ContainerID),
		})
		if result.Err != nil {
			reconciliationErrors = append(reconciliationErrors, fmt.Errorf("delete abandoned container %s: %w", metadata.ContainerID, result.Err))
			continue
		}
		if err := removeOwnedBundle(p.config.BundleRoot, bundle); err != nil {
			reconciliationErrors = append(reconciliationErrors, err)
		}
	}
	return errors.Join(reconciliationErrors...)
}

func runWasAttempted(bundle string) (bool, error) {
	_, err := os.Lstat(filepath.Join(bundle, attemptName))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func readMetadata(path string) (bundleMetadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return bundleMetadata{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return bundleMetadata{}, err
	}
	if info.Size() > 4<<10 {
		return bundleMetadata{}, errors.New("metadata exceeds 4096 bytes")
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var metadata bundleMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return bundleMetadata{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return bundleMetadata{}, errors.New("multiple metadata JSON values")
		}
		return bundleMetadata{}, err
	}
	return metadata, nil
}

func validContainerID(value string) bool {
	const prefix = "provenance-"
	if len(value) != len(prefix)+32 || value[:len(prefix)] != prefix {
		return false
	}
	for _, character := range value[len(prefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
