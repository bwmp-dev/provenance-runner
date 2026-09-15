//go:build linux

package gvisor

import (
	"context"
	"testing"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
)

func TestMeasuredBundlePreparationRequiresOwnedState(t *testing.T) {
	var b *measuredBundle
	if b.prepare(context.Background(), nil, measuredGuestCommand{}, "", np.MappedIdentity{}, nil, 1) == nil || b.checkPrepared(np.MappedIdentity{}) == nil {
		t.Fatal("missing preparation ownership admitted")
	}
	for _, mapping := range []np.MappedIdentity{{}, {UID: 1, GID: 1, OverflowUID: 1, OverflowGID: 2}, {UID: 1, GID: 1, OverflowUID: 2, OverflowGID: 1}, {UID: ^uint32(0), GID: 1, OverflowUID: 2, OverflowGID: 2}} {
		if validPreparationMapping(mapping) {
			t.Fatal("unsafe mapped identity admitted")
		}
	}
	if !validPreparationMapping(np.MappedIdentity{UID: 65532, GID: 65532, OverflowUID: 65533, OverflowGID: 65533}) {
		t.Fatal("distinct nonroot mapping refused")
	}
}
