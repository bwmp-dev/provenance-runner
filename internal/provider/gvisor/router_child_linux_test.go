//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"fmt"
	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"io"
	"os"
	"strings"
	"testing"
)

func TestRouterHolderRejectsHostileArguments(t *testing.T) {
	valid := []string{"10000000-0000-4000-8000-000000000001", "40000", "40000", "40001", "40001"}
	if _, ok := routerChildInputs(valid); !ok {
		t.Fatal("trusted mapping refused")
	}
	for _, args := range [][]string{nil, {"secret-value"}, append(append([]string{}, valid...), "command"), {valid[0], "0", "40000", "40001", "40001"}, {valid[0], "040000", "40000", "40001", "40001"}, {valid[0], "40000", "40000", "40000", "40001"}} {
		var out bytes.Buffer
		if RunRouterChild(args, &out) != runscFailureExitCode || strings.Contains(out.String(), "secret-value") {
			t.Fatal("unsafe holder rejection")
		}
	}
}

func assertRouterThreadsUnprivileged(t *testing.T, owner *RouterOwner) {
	t.Helper()
	assertRouterDNSOrigin(t, owner)
	if owner.child.Validate(owner.job.Lease.JobId) != nil {
		t.Fatal("router identity before capability observation")
	}
	path := fmt.Sprintf("/proc/%d/task", owner.cmd.Process.Pid)
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal("router task observation")
	}
	entries, err := directory.ReadDir(65)
	directory.Close()
	if (err != nil && err != io.EOF) || len(entries) == 0 || len(entries) > 64 {
		t.Fatal("router task bound")
	}
	for _, entry := range entries {
		file, err := os.Open(path + "/" + entry.Name() + "/status")
		if err != nil {
			t.Fatal("router thread status")
		}
		raw, err := io.ReadAll(io.LimitReader(file, 16385))
		file.Close()
		if err != nil || len(raw) > 16384 {
			t.Fatal("router thread status bound")
		}
		fields := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			key, value, ok := strings.Cut(line, ":")
			if ok {
				fields[key] = strings.TrimSpace(value)
			}
		}
		for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
			if fields[key] != "0000000000000000" {
				t.Fatal("router thread retained capabilities")
			}
		}
		if fields["NoNewPrivs"] != "1" {
			t.Fatal("router thread can gain privileges")
		}
	}
	if owner.child.Validate(owner.job.Lease.JobId) != nil {
		t.Fatal("router identity after capability observation")
	}
}

func TestRouterOwnerRejectsMissingAuthorityAndClosesEmptyState(t *testing.T) {
	if owner, err := StartRouterOwner(context.Background(), nil, nil, nil, np.MappedIdentity{}); owner != nil || err == nil {
		t.Fatal("missing owner accepted")
	}
	for _, owner := range []*RouterOwner{nil, {}} {
		if owner.Close(context.Background()) != nil || owner.Close(context.Background()) != nil {
			t.Fatal("empty owner cleanup")
		}
	}
}
