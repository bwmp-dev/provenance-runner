//go:build linux

package gvisor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
)

func testMeasuredUplinkRefusals(t *testing.T, ctx context.Context, j *np.HostUplinkJournal, private *np.PrivateJobLink, job *p.JobSpecification, tools np.RouteTools, host *os.File, execute func(context.Context, *os.File, np.ProtectedRouteTool, ...string) ([]byte, error)) {
	t.Helper()
	for _, mode := range []string{"uplink-alias-refusal", "uplink-journal-refusal"} {
		t.Run(mode, func(t *testing.T) {
			probe, err := j.Create(ctx, job, private)
			if probe != nil {
				t.Cleanup(func() {
					if probe.Close(context.Background()) != nil {
						t.Error("uplink probe cleanup")
					}
				})
			}
			if err != nil || probe.Validate(ctx) != nil {
				t.Fatal("uplink probe creation", err)
			}
			if other, err := j.Create(ctx, job, private); other != nil || err == nil {
				t.Fatal("occupied uplink slot admitted")
			}
			if j.Close() == nil || j.Recover(ctx) == nil || probe.Validate(ctx) != nil {
				t.Fatal("active uplink ownership lost")
			}
			var restore func() error
			if mode == "uplink-alias-refusal" {
				raw, err := execute(ctx, host, tools.IP, "-j", "-d", "link", "show")
				var rows []struct {
					Name  string `json:"ifname"`
					Alias string `json:"ifalias"`
				}
				if err != nil || json.Unmarshal(raw, &rows) != nil || len(rows) != 2 {
					t.Fatal("owned host peer observation")
				}
				name, alias := "", ""
				for _, row := range rows {
					if row.Name != "lo" {
						name, alias = row.Name, row.Alias
					}
				}
				if !strings.HasPrefix(name, "ph") || len(name) != 15 || !strings.HasSuffix(alias, ":host") {
					t.Fatal("owned host peer identity")
				}
				restore = func() error {
					cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					_, err := execute(cleanup, host, tools.IP, "link", "set", "dev", name, "alias", alias)
					return err
				}
				if _, err := execute(ctx, host, tools.IP, "link", "set", "dev", name, "alias", "foreign-fixture"); err != nil {
					t.Fatal("alias drift fixture")
				}
			} else {
				entries, err := os.ReadDir("/state-input/uplink-journal")
				if err != nil || len(entries) != 2 {
					t.Fatal("owned uplink intent inventory")
				}
				name := ""
				for _, entry := range entries {
					if strings.HasSuffix(entry.Name(), ".json") {
						name = entry.Name()
					}
				}
				if len(name) != 69 {
					t.Fatal("owned intent name")
				}
				path := filepath.Join("/state-input/uplink-journal", name)
				raw, err := os.ReadFile(path)
				if err != nil || len(raw) > 4096 {
					t.Fatal("owned intent contents")
				}
				restore = func() error { return os.WriteFile(path, raw, 0600) }
				if os.WriteFile(path, []byte("{}\n"), 0600) != nil {
					t.Fatal("intent drift fixture")
				}
			}
			restored := false
			t.Cleanup(func() {
				if !restored && restore() != nil {
					t.Error("owned uplink fixture restoration")
				}
			})
			if probe.Validate(ctx) == nil || probe.Close(ctx) == nil {
				t.Fatal("foreign uplink granted validation or deletion")
			}
			if restore() != nil {
				t.Fatal("owned uplink was deleted")
			}
			restored = true
			if probe.Validate(ctx) == nil || probe.Close(ctx) != nil {
				t.Fatal("uplink resumed or original cleanup refused")
			}
		})
	}
	t.Run("uplink-prefix-refusal", func(t *testing.T) {
		if _, err := execute(ctx, host, tools.IP, "route", "add", "10.0.2.0/24", "dev", "lo"); err != nil {
			t.Fatal("foreign prefix fixture")
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := execute(cleanup, host, tools.IP, "route", "del", "10.0.2.0/24", "dev", "lo"); err != nil {
				t.Error("foreign prefix fixture cleanup")
			}
		})
		if other, err := j.Create(ctx, job, private); other != nil || err == nil {
			t.Fatal("overlapping host network admitted")
		}
	})
}

func TestMeasuredHostUplinkCrashProcess(t *testing.T) {
	if os.Getenv("PROVENANCE_UPLINK_CRASH") != "1" {
		t.Skip("dedicated crash subprocess only")
	}
	testMeasuredAuthorityRouteSentry(t, "uplink-crash")
	t.Fatal("crash point not reached")
}

func TestMeasuredHostUplinkColdRecovery(t *testing.T) {
	requireMeasuredBundleFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMeasuredHostUplinkCrashProcess$")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "PROVENANCE_DISPOSABLE_NETWORK_FIXTURE=1", "PROVENANCE_DISPOSABLE_MEASURED_SENTRY_FIXTURE=1", "PROVENANCE_UPLINK_CRASH=1"}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL}
	if err := command.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
			t.Fatal("uplink crash point not reached", err)
		}
	} else {
		t.Fatal("controller did not crash")
	}
	entries, err := os.ReadDir("/state-input/uplink-journal")
	if err != nil || len(entries) != 2 {
		t.Fatal("crash did not retain one uplink intent")
	}
	bundles, cgroups := openBundleFixture(t)
	defer cgroups.Close()
	defer bundles.close()
	if bundles.recover(ctx) != nil {
		t.Fatal("cold process and bundle drainage")
	}
	load := func(name string) np.ProtectedRouteTool {
		t.Helper()
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatal("fixture tool lookup")
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal("fixture tool descriptor")
		}
		t.Cleanup(func() { file.Close() })
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			t.Fatal("fixture tool digest")
		}
		return np.ProtectedRouteTool{File: file, SHA256: [32]byte(hash.Sum(nil))}
	}
	state, err := os.Open("/state-input/uplink-journal")
	if err != nil {
		t.Fatal("cold uplink state")
	}
	journal, err := np.OpenHostUplinkJournal(state, np.RouteTools{NSenter: load("nsenter"), NFT: load("nft"), IP: load("ip")})
	state.Close()
	if err != nil {
		t.Fatal("cold uplink journal", err)
	}
	defer journal.Close()
	if journal.Recover(ctx) != nil {
		t.Fatal("cold uplink absence proof")
	}
	entries, err = os.ReadDir("/state-input/uplink-journal")
	if err != nil || len(entries) != 1 || entries[0].Name() != ".lock" {
		t.Fatal("uplink intent not retired")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("host peer survived cold recovery")
	}
	if journal.Close() != nil || bundles.close() != nil || cgroups.Close() != nil {
		t.Fatal("cold ownership handles remain")
	}
}
