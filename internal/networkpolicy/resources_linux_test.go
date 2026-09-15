//go:build linux

package networkpolicy

import (
	"os"
	"strings"
	"testing"
)

func TestResourceCPURequiresFairSchedulingAndNoRealtimeAllowance(t *testing.T) {
	fields := make([]string, 39)
	for i := range fields {
		fields[i] = "0"
	}
	limits := "Max realtime priority     0       0\n"
	for _, policy := range []string{"0", "3", "5"} {
		fields[38] = policy
		if !fairScheduler("1 (weird ) child) "+strings.Join(fields, " "), limits) {
			t.Fatal("fair-class process refused")
		}
	}
	for _, policy := range []string{"1", "2", "6", "7", "-1"} {
		fields[38] = policy
		if fairScheduler("1 (child) "+strings.Join(fields, " "), limits) {
			t.Fatal("scheduler can bypass CPU ceiling")
		}
	}
	fields[38] = "0"
	for _, bad := range []string{"", "Max realtime priority 0 1\n", "Max realtime priority 1 1\n", limits + limits} {
		if fairScheduler("1 (child) "+strings.Join(fields, " "), bad) {
			t.Fatal("realtime scheduling allowance accepted")
		}
	}
}

func TestResourceCgroupMembershipIsExactUnifiedPath(t *testing.T) {
	for _, raw := range []string{"0::/\n", "0::/user.slice/provenance-job.scope\n"} {
		if _, ok := unifiedCgroupPath(raw); !ok {
			t.Fatal("canonical path refused")
		}
	}
	for _, raw := range []string{"", "0::/", "1:cpu:/\n", "0::relative\n", "0::/../foreign\n", "0:://foreign\n", "0::/a/./b\n", "0::/a\n0::/b\n", "0::/bad\x00\n"} {
		if _, ok := unifiedCgroupPath(raw); ok {
			t.Fatal("ambiguous membership accepted")
		}
	}
}

func TestResourceBoundaryRejectsOrdinaryFilesAndEmptyOwners(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if protectedCgroup(dir, true) {
		t.Fatal("ordinary directory treated as kernel cgroup")
	}
	if r, err := RetainResources(nil, nil, dir); err != ErrResources || r != nil {
		t.Fatal("missing owned child accepted")
	}
	var empty *RetainedResources
	if empty.ValidateForChild(nil, nil) != ErrResources {
		t.Fatal("nil resource proof accepted an exact child")
	}
	if empty.Validate(nil) != ErrResources || empty.Close() != nil {
		t.Fatal("nil boundary granted proof")
	}
	empty = &RetainedResources{}
	if empty.Validate(nil) != ErrResources || !empty.invalid || empty.Close() != nil || empty.Close() != nil {
		t.Fatal("zero boundary granted proof or broke idempotent close")
	}
}

func TestResourceExactChildMismatchPermanentlyInvalidatesProof(t *testing.T) {
	for _, foreign := range []*ChildNamespaces{nil, {}} {
		owned := &ChildNamespaces{}
		r := &RetainedResources{child: owned}
		if r.ValidateForChild(nil, foreign) != ErrResources || !r.invalid {
			t.Fatal("foreign child did not invalidate resource proof")
		}
		if owned.closed {
			t.Fatal("resource refusal invalidated independently retained child")
		}
	}
}
