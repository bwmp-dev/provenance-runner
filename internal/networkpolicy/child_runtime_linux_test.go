//go:build linux

package networkpolicy

import "testing"

func TestRuntimeObjectsRequireLiveOwnerAndClosedRootLocation(t *testing.T) {
	job := "70000000-0000-4000-8000-000000000001"
	for _, child := range []*ChildNamespaces{nil, {}} {
		for _, path := range []string{"", "/", "relative", "/tmp/" + job + "/.measured-root", "/tmp/" + job + "/../.measured-root", "/tmp/foreign/.measured-root", "/tmp/" + job + "/inputs", "/tmp/" + job + "/.measured-root/", "/tmp/\x00/" + job + "/.measured-root"} {
			exe, root, err := child.RuntimeObjectsForJob(job, path)
			if err == nil || exe != nil || root != nil {
				t.Fatal("invalid runtime observation returned descriptors")
			}
		}
	}
}
