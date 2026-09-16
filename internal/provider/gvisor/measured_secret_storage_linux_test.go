//go:build linux

package gvisor

import (
	"context"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
)

func TestMeasuredSecretStorageRequiresOwnership(t *testing.T) {
	if stageMeasuredSecrets(context.Background(), nil, nil, np.MappedIdentity{}, time.Now().Add(time.Minute)) == nil {
		t.Fatal("missing ownership accepted")
	}
}
