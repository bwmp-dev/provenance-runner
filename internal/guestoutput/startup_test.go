package guestoutput

import (
	"bytes"
	"strings"
	"testing"
)

func TestStartupIsExactAndLeavesFollowingFramesUntouched(t *testing.T) {
	var wire bytes.Buffer
	if WriteStartup(&wire) != nil {
		t.Fatal("write")
	}
	wire.WriteString("following")
	if ReadStartup(&wire) != nil || wire.String() != "following" {
		t.Fatal("startup framing")
	}
	for _, raw := range []string{"", "PVREADY", "PVREADY2", "untrustd"} {
		if ReadStartup(strings.NewReader(raw)) == nil {
			t.Fatal("invalid marker accepted")
		}
	}
	if WriteStartup(nil) == nil || ReadStartup(nil) == nil {
		t.Fatal("nil startup IO")
	}
}
