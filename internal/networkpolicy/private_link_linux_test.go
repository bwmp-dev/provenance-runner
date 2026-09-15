//go:build linux

package networkpolicy

import (
	"context"
	"testing"
)

func TestPrivateJobLinkRejectsMissingOwners(t *testing.T) {
	if link, err := CreatePrivateJobLink(context.Background(), "", nil, nil, RouteTools{}); link != nil || err == nil {
		t.Fatal("missing namespace owners accepted")
	}
	for _, link := range []*PrivateJobLink{nil, {}} {
		if link.Validate(context.Background()) == nil || link.Close(context.Background()) != nil || link.Close(context.Background()) != nil {
			t.Fatal("empty private link handling")
		}
	}
}
