package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	workspaceMarkerName    = ".provenance-workspace.json"
	workspaceMarkerVersion = 1
)

type workspaceMarker struct {
	Version   int       `json:"version"`
	JobID     string    `json:"jobId"`
	CreatedAt time.Time `json:"createdAt"`
}

func (m *Manager) Reconcile(ctx context.Context, now time.Time) error {
	return m.reconcile(ctx, now, false)
}

// ReconcileOwnedAttempts removes every valid owned workspace after the caller
// has acquired the runner's exclusive instance lock. It must not be used while
// another process can own workspaces beneath the same manager root.
func (m *Manager) ReconcileOwnedAttempts(ctx context.Context) error {
	return m.reconcile(ctx, time.Now().UTC(), true)
}

func (m *Manager) reconcile(ctx context.Context, now time.Time, removeFresh bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(m.root)
	if err != nil {
		return fmt.Errorf("reconcile workspaces: %w", err)
	}
	var reconciliationErrors []error
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "provenance-job-") {
			continue
		}
		root := filepath.Join(m.root, entry.Name())
		info, err := os.Lstat(root)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			reconciliationErrors = append(reconciliationErrors, fmt.Errorf("inspect workspace %q: invalid owned directory", entry.Name()))
			continue
		}
		marker, err := readWorkspaceMarker(filepath.Join(root, workspaceMarkerName))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			reconciliationErrors = append(reconciliationErrors, fmt.Errorf("inspect workspace %q: %w", entry.Name(), err))
			continue
		}
		if marker.Version != workspaceMarkerVersion || marker.JobID == "" || len(marker.JobID) > 128 || marker.CreatedAt.IsZero() || marker.CreatedAt.After(now) {
			reconciliationErrors = append(reconciliationErrors, fmt.Errorf("inspect workspace %q: invalid ownership marker", entry.Name()))
			continue
		}
		if !removeFresh && now.Sub(marker.CreatedAt) < m.orphanTTL {
			continue
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(append(reconciliationErrors, err)...)
		}
		if err := ensureDescendant(m.root, root); err != nil {
			reconciliationErrors = append(reconciliationErrors, err)
			continue
		}
		if err := os.RemoveAll(root); err != nil {
			reconciliationErrors = append(reconciliationErrors, fmt.Errorf("remove orphan workspace %q: %w", entry.Name(), err))
		}
	}
	return errors.Join(reconciliationErrors...)
}

func writeWorkspaceMarker(root, jobID string, createdAt time.Time) error {
	path := filepath.Join(root, workspaceMarkerName)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write workspace ownership marker: %w", err)
	}
	encoder := json.NewEncoder(file)
	encodeErr := encoder.Encode(workspaceMarker{Version: workspaceMarkerVersion, JobID: jobID, CreatedAt: createdAt})
	if encodeErr == nil {
		encodeErr = file.Sync()
	}
	closeErr := file.Close()
	if encodeErr != nil || closeErr != nil {
		var writeErrors []error
		if encodeErr != nil {
			writeErrors = append(writeErrors, fmt.Errorf("write workspace ownership marker: %w", encodeErr))
		}
		if closeErr != nil {
			writeErrors = append(writeErrors, closeErr)
		}
		return errors.Join(writeErrors...)
	}
	return nil
}

func readWorkspaceMarker(path string) (workspaceMarker, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return workspaceMarker{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<10 {
		return workspaceMarker{}, errors.New("ownership marker is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return workspaceMarker{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var marker workspaceMarker
	if err := decoder.Decode(&marker); err != nil {
		return workspaceMarker{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return workspaceMarker{}, errors.New("ownership marker has trailing JSON")
	}
	return marker, nil
}
